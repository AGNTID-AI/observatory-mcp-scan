// Package toolintel provides deterministic, protocol-neutral tool intelligence.
// It is intentionally independent from scanner, storage, MCP SDK, and HTTP types
// so it can later move into a shared AgntID service without changing callers.
package toolintel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

const (
	TaxonomyVersion    = 1
	ClassifierRevision = "2026-07-22-observatory-v3"
)

type Annotations struct {
	Title           string
	ReadOnlyHint    *bool
	DestructiveHint *bool
	IdempotentHint  *bool
	OpenWorldHint   *bool
}

type Tool struct {
	Name         string
	Description  string
	InputSchema  map[string]any
	OutputSchema map[string]any
	Annotations  Annotations
}

type Confidence struct {
	Band     string
	Score    float64
	Evidence []string
}

type Classification struct {
	OperationType            string
	Domain                   string
	BlastRadius              string
	Sensitivity              string
	Criticality              string
	PrivilegeLevel           int
	IsMutating               bool
	IsDiscover               bool
	ExecutionSurface         string
	Effects                  []string
	ConfidenceBand           string
	PerDimensionConfidence   map[string]Confidence
	Evidence                 []string
	AnnotationContradictions []string
}

type SchemaSignal struct {
	Code, Severity, Path, Message string
}

// InputRisk describes an agent-controlled field that can cross a sensitive
// execution boundary. It is derived only from the advertised schema.
type InputRisk struct {
	Kind, Path, Severity, Reason string
	Constrained                  bool
}

type SchemaAnalysis struct {
	Valid                    bool
	HasOutputSchema          bool
	AdditionalProperties     string
	PropertyCount            int
	RequiredCount            int
	DescribedPropertyCount   int
	DescriptionCoverage      float64
	MaxDepth                 int
	UnconstrainedStringCount int
	SensitiveFields          []string
	DangerousFields          []string
	InputRisks               []InputRisk
	Signals                  []SchemaSignal
}

type PolicyDecision struct {
	Profile          string
	Disposition      string
	Reasons          []string
	RequiresApproval bool
}

type Analysis struct {
	Classification Classification
	Schema         SchemaAnalysis
	Policy         map[string]PolicyDecision
	Fingerprint    string
	Risk           string
	Categories     []string
}

func Analyze(tool Tool) Analysis {
	schema := AnalyzeSchema(tool.InputSchema, tool.OutputSchema)
	classification := Classify(tool, schema)
	return Analysis{
		Classification: classification,
		Schema:         schema,
		Policy:         PreviewPolicies(classification),
		Fingerprint:    ToolFingerprint(tool),
		Risk:           Risk(classification),
		Categories:     categories(classification),
	}
}

func Classify(tool Tool, schema SchemaAnalysis) Classification {
	name := normalize(tool.Name)
	description := normalize(tool.Description)
	schemaText := normalize(strings.Join(append(schema.SensitiveFields, schema.DangerousFields...), " "))
	combined := strings.Join([]string{name, description, schemaText}, " ")

	operation, operationEvidence, operationScore := inferOperation(name, description)
	operation, operationEvidence, operationScore = resolveReadOnlyOperation(tool.Annotations, name, description, operation, operationEvidence, operationScore)
	domain, domainEvidence, domainScore := inferDomain(combined)
	effects, effectEvidence := inferEffects(operation, combined, tool.Annotations)
	blast, blastEvidence := inferBlast(operation, combined)
	sensitivity, sensitivityEvidence := inferSensitivity(domain, combined, effects)
	criticality := inferCriticality(operation, blast, sensitivity, effects)
	surface, surfaceEvidence, surfaceScore := inferSurface(combined)
	mutating := operation == "WRITE" || operation == "CREATE" || operation == "DELETE" || operation == "EXECUTE" || contains(effects, "STATE_PERSISTENCE")
	discover := operation == "READ" || operation == "LIST"
	privilege := map[string]int{"READ": 1, "LIST": 1, "WRITE": 2, "CREATE": 2, "DELETE": 3, "EXECUTE": 3, "OTHER": 2}[operation]

	evidence := append([]string{}, operationEvidence...)
	evidence = append(evidence, domainEvidence...)
	evidence = append(evidence, effectEvidence...)
	evidence = append(evidence, blastEvidence, sensitivityEvidence, surfaceEvidence)
	evidence = compact(evidence)

	perDimension := map[string]Confidence{
		"operation_type":    confidence(operationScore, operationEvidence),
		"domain":            confidence(domainScore, domainEvidence),
		"blast_radius":      confidence(scoreFor(blast != "SINGLE_RECORD", .82, .56), []string{blastEvidence}),
		"sensitivity":       confidence(scoreFor(sensitivity == "LOW", .58, .84), []string{sensitivityEvidence}),
		"criticality":       confidence(scoreFor(criticality == "STANDARD", .58, .84), []string{"derived from operation, blast radius, sensitivity, and effects"}),
		"execution_surface": confidence(surfaceScore, []string{surfaceEvidence}),
		"effects":           confidence(scoreFor(len(effects) == 1 && effects[0] == "READ", .62, .88), effectEvidence),
	}
	band := "HIGH"
	for _, dimension := range perDimension {
		if rankBand(dimension.Band) < rankBand(band) {
			band = dimension.Band
		}
	}

	contradictions := annotationContradictions(tool.Annotations, mutating, effects)
	return Classification{
		OperationType:            operation,
		Domain:                   domain,
		BlastRadius:              blast,
		Sensitivity:              sensitivity,
		Criticality:              criticality,
		PrivilegeLevel:           privilege,
		IsMutating:               mutating,
		IsDiscover:               discover,
		ExecutionSurface:         surface,
		Effects:                  effects,
		ConfidenceBand:           band,
		PerDimensionConfidence:   perDimension,
		Evidence:                 evidence,
		AnnotationContradictions: contradictions,
	}
}

func AnalyzeSchema(input, output map[string]any) SchemaAnalysis {
	a := SchemaAnalysis{Valid: input != nil, HasOutputSchema: len(output) > 0, AdditionalProperties: "unspecified", SensitiveFields: []string{}, DangerousFields: []string{}, InputRisks: []InputRisk{}, Signals: []SchemaSignal{}}
	if input == nil {
		a.Signals = append(a.Signals, SchemaSignal{Code: "schema.missing", Severity: "high", Message: "Input schema is missing or null."})
		return a
	}
	if typ, ok := input["type"].(string); !ok || typ != "object" {
		a.Valid = false
		a.Signals = append(a.Signals, SchemaSignal{Code: "schema.root_type", Severity: "high", Path: "$", Message: "Input schema root should declare type object."})
	}
	if value, ok := input["additionalProperties"]; ok {
		if allowed, ok := value.(bool); ok && !allowed {
			a.AdditionalProperties = "forbidden"
		} else {
			a.AdditionalProperties = "allowed"
			a.Signals = append(a.Signals, SchemaSignal{Code: "schema.additional_properties", Severity: "medium", Path: "$", Message: "Input schema permits undeclared properties."})
		}
	} else {
		a.Signals = append(a.Signals, SchemaSignal{Code: "schema.additional_properties_unspecified", Severity: "medium", Path: "$", Message: "Input schema does not explicitly reject undeclared properties."})
	}
	required := stringSet(input["required"])
	a.RequiredCount = len(required)
	walkSchema(input, "$", 1, required, &a)
	if a.PropertyCount > 0 {
		a.DescriptionCoverage = float64(a.DescribedPropertyCount) / float64(a.PropertyCount) * 100
		if a.DescriptionCoverage < 70 {
			a.Signals = append(a.Signals, SchemaSignal{Code: "schema.description_coverage", Severity: "medium", Message: fmt.Sprintf("Only %.0f%% of input fields are described.", a.DescriptionCoverage)})
		}
	}
	if !a.HasOutputSchema {
		a.Signals = append(a.Signals, SchemaSignal{Code: "schema.output_missing", Severity: "low", Message: "No output schema is advertised for structured result validation."})
	}
	sort.Strings(a.SensitiveFields)
	sort.Strings(a.DangerousFields)
	return a
}

func walkSchema(node map[string]any, path string, depth int, required map[string]bool, a *SchemaAnalysis) {
	if depth > a.MaxDepth {
		a.MaxDepth = depth
	}
	if depth > 8 {
		a.Signals = append(a.Signals, SchemaSignal{Code: "schema.depth", Severity: "medium", Path: path, Message: "Schema nesting exceeds eight levels."})
		return
	}
	properties, _ := node["properties"].(map[string]any)
	for name, raw := range properties {
		child, ok := raw.(map[string]any)
		if !ok {
			a.Valid = false
			a.Signals = append(a.Signals, SchemaSignal{Code: "schema.property_invalid", Severity: "high", Path: path + "." + name, Message: "Property definition is not a JSON Schema object."})
			continue
		}
		a.PropertyCount++
		childPath := path + "." + name
		if strings.TrimSpace(asString(child["description"])) != "" {
			a.DescribedPropertyCount++
		}
		fieldName := normalizeIdentifier(name)
		description := normalize(asString(child["description"]))
		lower := normalize(fieldName + " " + description)
		kinds := inputRiskKinds(fieldName, description)
		if contains(kinds, "CREDENTIAL") {
			a.SensitiveFields = append(a.SensitiveFields, childPath)
		}
		nonCredentialBoundary := false
		for _, kind := range kinds {
			if kind != "CREDENTIAL" {
				nonCredentialBoundary = true
			}
		}
		if nonCredentialBoundary || hasAny(lower, "force", "recursive", "overwrite") {
			a.DangerousFields = append(a.DangerousFields, childPath)
		}
		constrained := child["enum"] != nil || child["pattern"] != nil || child["format"] != nil || child["const"] != nil
		for _, kind := range kinds {
			severity := "medium"
			if kind == "COMMAND" || kind == "CREDENTIAL" {
				severity = "high"
			}
			a.InputRisks = append(a.InputRisks, InputRisk{Kind: kind, Path: childPath, Severity: severity, Constrained: constrained, Reason: inputRiskReason(kind, constrained)})
		}
		if asString(child["type"]) == "string" && child["enum"] == nil && child["pattern"] == nil && child["format"] == nil && child["maxLength"] == nil {
			a.UnconstrainedStringCount++
			severity := "low"
			if hasAny(lower, "command", "shell", "sql", "path", "url", "uri", "host", "endpoint") {
				severity = "medium"
			}
			a.Signals = append(a.Signals, SchemaSignal{Code: "schema.unconstrained_string", Severity: severity, Path: childPath, Message: "String field has no enum, pattern, format, or length constraint."})
		}
		childRequired := stringSet(child["required"])
		walkSchema(child, childPath, depth+1, childRequired, a)
		if items, ok := child["items"].(map[string]any); ok {
			walkSchema(items, childPath+"[]", depth+1, stringSet(items["required"]), a)
		}
	}
}

func inputRiskKinds(fieldName, description string) []string {
	kinds := []string{}
	fieldText := normalize(fieldName)
	descriptionText := normalize(description)
	text := normalize(fieldText + " " + descriptionText)
	identifier := hasAny(fieldText, "id", "identifier", "reference", "name", "handle") || hasAny(descriptionText, "identifier", "reference", "name", "handle")
	inspectionContent := credentialInspectionContext(text) || hasAny(descriptionText, "file content", "raw content", "snippet", "diff hunk", "not repository file path")
	credentialName := hasAny(fieldText, "secret", "token", "password", "credential", "private key", "api key")
	credentialDescription := hasAny(descriptionText, "credential value", "secret value", "access token", "bearer token", "api token", "password value", "private key")
	credential := !identifier && !inspectionContent && (credentialName || credentialDescription)
	if credential {
		kinds = append(kinds, "CREDENTIAL")
	}
	if hasAny(text, "command", "shell", "script", "exec") {
		kinds = append(kinds, "COMMAND")
	}
	if hasAny(text, "sql", "sql query", "database query") {
		kinds = append(kinds, "QUERY")
	}
	pathName := hasAny(fieldText, "path", "file path", "directory", "filesystem path")
	pathDescription := hasAny(descriptionText, "file path", "directory path", "filesystem path", "path to")
	if !inspectionContent && (pathName || pathDescription) {
		kinds = append(kinds, "PATH")
	}
	urlName := hasAny(fieldText, "url", "uri", "host", "endpoint", "webhook", "destination")
	urlDescription := hasAny(descriptionText, "destination url", "callback url", "webhook url", "endpoint url", "url to", "uri to", "network destination", "remote endpoint")
	if urlName || urlDescription {
		kinds = append(kinds, "URL")
	}
	return compact(kinds)
}

func inputRiskReason(kind string, constrained bool) string {
	boundary := map[string]string{
		"CREDENTIAL": "credential material may enter model-visible tool arguments",
		"COMMAND":    "model-generated text may reach a command or script boundary",
		"QUERY":      "model-generated text may reach a database query boundary",
		"PATH":       "model-generated text may select a filesystem path",
		"URL":        "model-generated text may select a network destination",
	}[kind]
	if constrained {
		return boundary + "; the schema declares a format, pattern, enum, or constant"
	}
	return boundary + "; no format, pattern, enum, or constant is declared"
}

func PreviewPolicies(c Classification) map[string]PolicyDecision {
	dangerous := intersect(c.Effects, []string{"DESTRUCTIVE", "CREDENTIAL_ACCESS", "PRIVILEGE_ESCALATION", "CODE_EXECUTION"})
	readOnlyReasons := []string{}
	if c.OperationType != "READ" && c.OperationType != "LIST" {
		readOnlyReasons = append(readOnlyReasons, "Read Only permits only READ and LIST operations")
	}
	if c.IsMutating {
		readOnlyReasons = append(readOnlyReasons, "Tool is inferred to mutate state")
	}
	if len(dangerous) > 0 {
		readOnlyReasons = append(readOnlyReasons, "Blocked effects: "+strings.Join(dangerous, ", "))
	}
	readOnly := decision("read-only", readOnlyReasons, false)

	readWriteReasons := []string{}
	if c.OperationType == "DELETE" || c.OperationType == "EXECUTE" || c.OperationType == "OTHER" {
		readWriteReasons = append(readWriteReasons, "Read Write excludes DELETE, EXECUTE, and unknown operations")
	}
	blockedRW := intersect(c.Effects, []string{"DESTRUCTIVE", "CREDENTIAL_ACCESS", "PRIVILEGE_ESCALATION"})
	if len(blockedRW) > 0 {
		readWriteReasons = append(readWriteReasons, "Blocked effects: "+strings.Join(blockedRW, ", "))
	}
	if c.Sensitivity == "CRITICAL" {
		readWriteReasons = append(readWriteReasons, "Critical sensitivity requires a narrower policy")
	}
	readWrite := decision("read-write", readWriteReasons, false)

	protectedReasons := []string{}
	requiresApproval := c.OperationType == "DELETE" || c.OperationType == "EXECUTE" || len(dangerous) > 0 || (c.IsMutating && (c.BlastRadius == "SERVICE_WIDE" || c.BlastRadius == "GLOBAL"))
	if requiresApproval {
		protectedReasons = append(protectedReasons, "AgntID should require explicit policy or approval for this capability")
	}
	protected := decision("protected", protectedReasons, requiresApproval)
	return map[string]PolicyDecision{"read-only": readOnly, "read-write": readWrite, "protected": protected}
}

func decision(profile string, reasons []string, approval bool) PolicyDecision {
	disposition := "visible"
	if len(reasons) > 0 && !approval {
		disposition = "hidden"
	}
	if approval {
		disposition = "approval"
	}
	return PolicyDecision{Profile: profile, Disposition: disposition, Reasons: reasons, RequiresApproval: approval}
}

func ToolFingerprint(tool Tool) string {
	canonical := map[string]any{"name": tool.Name, "description": tool.Description, "inputSchema": tool.InputSchema, "outputSchema": tool.OutputSchema, "annotations": tool.Annotations}
	b, _ := json.Marshal(canonical)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func CatalogFingerprint(tools []Tool) string {
	items := append([]Tool(nil), tools...)
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	parts := make([]string, 0, len(items))
	for _, tool := range items {
		parts = append(parts, ToolFingerprint(tool))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])
}

func Risk(c Classification) string {
	if c.Criticality == "CRITICAL" || c.Sensitivity == "CRITICAL" || len(intersect(c.Effects, []string{"DESTRUCTIVE", "CREDENTIAL_ACCESS", "PRIVILEGE_ESCALATION", "CODE_EXECUTION", "DATA_EXFILTRATION"})) > 0 {
		return "high"
	}
	if c.IsMutating || c.Sensitivity == "HIGH" || c.BlastRadius == "SERVICE_WIDE" {
		return "medium"
	}
	return "low"
}

func categories(c Classification) []string {
	out := []string{title(c.Domain)}
	for _, effect := range c.Effects {
		switch effect {
		case "CREDENTIAL_ACCESS":
			out = append(out, "Secrets")
		case "CODE_EXECUTION":
			out = append(out, "Execution")
		case "NETWORK_EGRESS", "EXTERNAL_SERVICE_CALL":
			out = append(out, "Network")
		}
	}
	return compact(out)
}

func inferOperation(name, description string) (string, []string, float64) {
	rules := []struct {
		operation string
		words     []string
	}{
		{"DELETE", []string{"delete", "remove", "destroy", "purge", "wipe", "erase", "terminate", "revoke", "drop"}},
		{"EXECUTE", []string{"execute", "run", "invoke", "trigger", "restart", "shell", "command", "deploy"}},
		{"CREATE", []string{"create", "add", "fork", "insert", "provision", "launch", "new", "open"}},
		{"WRITE", []string{"write", "update", "set", "edit", "modify", "patch", "configure", "rename", "move", "upload", "push", "submit", "resolve", "assign", "send", "publish", "merge", "rotate"}},
		{"LIST", []string{"list", "search", "find", "scan", "enumerate", "browse", "discover"}},
		{"READ", []string{"read", "get", "show", "fetch", "describe", "view", "inspect", "download", "validate", "calculate", "analyze"}},
	}
	// MCP tool names conventionally begin with the action verb. Prefer that
	// verb so resource nouns such as get_status_updates do not turn a read into
	// a write merely because a later token happens to be "updates".
	if tokens := strings.Fields(normalize(name)); len(tokens) > 0 {
		for _, rule := range rules {
			if word, ok := firstMatch(tokens[0], rule.words); ok {
				return rule.operation, []string{"leading tool-name verb matched operation keyword " + word}, .97
			}
		}
	}
	for _, rule := range rules {
		if word, ok := firstMatch(name, rule.words); ok {
			return rule.operation, []string{"tool name matched operation keyword " + word}, .96
		}
	}
	for _, rule := range rules {
		if word, ok := firstMatch(description, rule.words); ok {
			return rule.operation, []string{"description matched operation keyword " + word}, .76
		}
	}
	return "OTHER", []string{"no deterministic operation keyword matched"}, .32
}

func resolveReadOnlyOperation(annotations Annotations, name, description, operation string, evidence []string, score float64) (string, []string, float64) {
	if annotations.ReadOnlyHint == nil || !*annotations.ReadOnlyHint || operation == "READ" || operation == "LIST" {
		return operation, evidence, score
	}
	strongMutation := hasAny(name, "delete", "remove", "destroy", "purge", "wipe", "erase", "terminate", "revoke", "drop", "create", "add", "fork", "insert", "provision", "launch", "write", "update", "set", "edit", "modify", "patch", "configure", "rename", "move", "upload", "push", "submit", "resolve", "assign", "send", "publish", "merge", "rotate")
	if strongMutation {
		return operation, evidence, score
	}
	readText := normalize(name + " " + description)
	if word, ok := firstMatch(readText, []string{"list", "search", "find", "scan", "enumerate", "browse", "discover"}); ok {
		return "LIST", []string{"readOnlyHint=true resolved an ambiguous operation; metadata matched " + word}, .9
	}
	if word, ok := firstMatch(readText, []string{"read", "get", "show", "fetch", "describe", "view", "inspect", "download", "validate", "calculate", "analyze"}); ok {
		return "READ", []string{"readOnlyHint=true resolved an ambiguous operation; metadata matched " + word}, .9
	}
	return operation, evidence, score
}

func inferDomain(text string) (string, []string, float64) {
	if credentialInspectionContext(text) && hasAny(text, "file", "content", "snippet", "diff", "codebase", "repository") {
		return "FILESYSTEM", []string{"metadata describes inspection of supplied file or diff content"}, .9
	}
	rules := []struct {
		domain string
		words  []string
	}{
		{"CLOUD_STORAGE", []string{"s3", "bucket", "blob", "gcs", "storage", "drive"}},
		{"IDENTITY", []string{"user", "role", "permission", "iam", "credential", "oauth", "token", "secret", "password"}},
		{"DATABASE", []string{"database", "table", "query", "sql", "record"}},
		{"COMPUTE", []string{"instance", "container", "lambda", "compute", "kubernetes", "pod", "docker"}},
		{"NETWORK", []string{"network", "vpc", "subnet", "firewall", "dns", "route", "url", "endpoint", "webhook"}},
		{"MESSAGING", []string{"message", "email", "slack", "channel", "notification", "queue", "topic"}},
		{"VCS", []string{"git", "repository", "repo", "commit", "branch", "pull request", "issue"}},
		{"FILESYSTEM", []string{"file", "directory", "path", "folder", "filesystem"}},
	}
	for _, rule := range rules {
		if word, ok := firstMatch(text, rule.words); ok {
			return rule.domain, []string{"metadata matched domain keyword " + word}, .88
		}
	}
	return "GENERAL", []string{"domain defaulted to general"}, .42
}

func inferEffects(operation, text string, annotations Annotations) ([]string, []string) {
	set := map[string]string{}
	add := func(effect, reason string) {
		if _, ok := set[effect]; !ok {
			set[effect] = reason
		}
	}
	if operation == "READ" || operation == "LIST" {
		add("READ", "operation is "+operation)
	} else {
		add("WRITE", "operation is "+operation)
		add("STATE_PERSISTENCE", "operation may mutate state")
	}
	checks := []struct {
		effect string
		words  []string
	}{
		{"DESTRUCTIVE", []string{"delete", "destroy", "purge", "wipe", "drop", "terminate", "remove"}},
		{"PRIVILEGE_ESCALATION", []string{"sudo", "chmod", "chown", "grant role", "privilege", "iam attach", "role assign"}},
		{"DATA_EXFILTRATION", []string{"exfil", "export", "send to", "upload external", "transmit"}},
		{"CODE_EXECUTION", []string{"execute command", "shell command", "run script", "ssh", "docker run", "kubectl"}},
		{"NETWORK_EGRESS", []string{"send to", "publish to", "upload external", "webhook", "outbound"}},
		{"EXTERNAL_SERVICE_CALL", []string{"external", "third party", "saas", "api call", "email", "slack"}},
	}
	for _, check := range checks {
		if word, ok := firstMatch(text, check.words); ok {
			add(check.effect, "metadata matched "+word)
		}
	}
	if ok, reason := credentialAccessSignal(operation, text); ok {
		add("CREDENTIAL_ACCESS", reason)
	}
	if operation != "READ" && operation != "LIST" && hasAny(text, "comment", "reply", "review", "pull request", "issue") {
		add("NETWORK_EGRESS", "mutating operation can publish content to a remote collaboration surface")
	}
	if annotations.DestructiveHint != nil && *annotations.DestructiveHint {
		add("DESTRUCTIVE", "server annotation destructiveHint=true")
	}
	if annotations.OpenWorldHint != nil && *annotations.OpenWorldHint {
		add("EXTERNAL_SERVICE_CALL", "server annotation openWorldHint=true")
	}
	effects := make([]string, 0, len(set))
	evidence := make([]string, 0, len(set))
	for effect := range set {
		effects = append(effects, effect)
	}
	sort.Strings(effects)
	for _, effect := range effects {
		evidence = append(evidence, effect+": "+set[effect])
	}
	return effects, evidence
}

func inferBlast(operation, text string) (string, string) {
	if hasAny(text, "all", "global", "account wide", "tenant wide", "cluster wide", "recursive", "bulk") {
		return "GLOBAL", "metadata contains broad-scope or bulk language"
	}
	if credentialInspectionContext(text) && hasAny(text, "targeted", "specific files", "snippet", "diff hunk") {
		return "MULTI_RECORD", "metadata limits inspection to explicitly supplied items"
	}
	if hasAny(text, "service", "database", "repository", "bucket", "namespace", "table") {
		if operation == "READ" || operation == "LIST" {
			return "SERVICE_WIDE", "read or discovery operation can span a service-level resource"
		}
		return "SERVICE_WIDE", "mutating operation targets a service-level resource"
	}
	if hasAny(text, "batch", "many", "multiple", "list of") {
		return "MULTI_RECORD", "metadata indicates multiple records"
	}
	return "SINGLE_RECORD", "no broad blast-radius signal observed"
}

func credentialAccessSignal(operation, text string) (bool, string) {
	if credentialInspectionContext(text) || hasAny(text, "current credential", "using credential", "with credential") {
		return false, ""
	}
	if hasAny(text, "get secret", "read secret", "retrieve secret", "list secret", "fetch secret", "return secret", "secret value", "access token value", "bearer token", "password value", "private key") {
		return true, "metadata indicates credential material can be read or returned"
	}
	if operation != "READ" && operation != "LIST" && hasAny(text, "credential", "secret", "token", "password", "private key", "api key") {
		return true, "mutating operation manages credential or secret material"
	}
	return false, ""
}

func inferSensitivity(domain, text string, effects []string) (string, string) {
	if contains(effects, "CREDENTIAL_ACCESS") {
		return "CRITICAL", "credential or secret access signal"
	}
	if credentialInspectionContext(text) {
		return "HIGH", "tool may inspect supplied content that contains secrets"
	}
	if hasAny(text, "private key", "password", "secret value") {
		return "CRITICAL", "credential or secret access signal"
	}
	if hasAny(text, "pii", "personal data", "customer record", "financial", "medical", "production") {
		return "HIGH", "sensitive data language observed"
	}
	if domain == "IDENTITY" || domain == "DATABASE" || domain == "FILESYSTEM" {
		return "MEDIUM", "domain commonly carries sensitive data"
	}
	return "LOW", "no elevated sensitivity signal observed"
}

func inferCriticality(operation, blast, sensitivity string, effects []string) string {
	if sensitivity == "CRITICAL" || blast == "GLOBAL" || contains(effects, "PRIVILEGE_ESCALATION") {
		return "CRITICAL"
	}
	if operation == "DELETE" || operation == "EXECUTE" || blast == "SERVICE_WIDE" || sensitivity == "HIGH" {
		return "ELEVATED"
	}
	return "STANDARD"
}

func inferSurface(text string) (string, string, float64) {
	rules := []struct {
		surface string
		words   []string
	}{
		{"KUBERNETES_CLUSTER", []string{"kubernetes", "kubectl", "pod", "namespace"}},
		{"CONTAINER_RUNTIME", []string{"docker", "container"}},
		{"BROWSER_SESSION", []string{"browser", "playwright", "selenium", "page navigate"}},
		{"HUMAN_IDENTITY_PROVIDER", []string{"okta", "auth0", "ldap", "scim", "identity provider"}},
		{"FILESYSTEM_ACCESS", []string{"filesystem", "file path", "directory"}},
	}
	for _, rule := range rules {
		if word, ok := firstMatch(text, rule.words); ok {
			return rule.surface, "metadata matched execution-surface keyword " + word, .87
		}
	}
	return "REMOTE_API", "remote API is the conservative discovery-time fallback", .38
}

func annotationContradictions(a Annotations, mutating bool, effects []string) []string {
	out := []string{}
	if a.ReadOnlyHint != nil && *a.ReadOnlyHint && mutating {
		out = append(out, "readOnlyHint=true conflicts with inferred mutation")
	}
	if a.DestructiveHint != nil && !*a.DestructiveHint && contains(effects, "DESTRUCTIVE") {
		out = append(out, "destructiveHint=false conflicts with destructive metadata signals")
	}
	return out
}

func confidence(score float64, evidence []string) Confidence {
	band := "LOW"
	if score >= .8 {
		band = "HIGH"
	} else if score >= .55 {
		band = "MEDIUM"
	}
	return Confidence{Band: band, Score: score, Evidence: compact(evidence)}
}
func rankBand(v string) int {
	if v == "HIGH" {
		return 2
	}
	if v == "MEDIUM" {
		return 1
	}
	return 0
}
func scoreFor(condition bool, yes, no float64) float64 {
	if condition {
		return yes
	}
	return no
}
func normalize(s string) string {
	return strings.Join(strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !(unicode.IsLetter(r) || unicode.IsDigit(r)) }), " ")
}

func normalizeIdentifier(s string) string {
	var b strings.Builder
	var previous rune
	for i, r := range s {
		if i > 0 && unicode.IsUpper(r) && (unicode.IsLower(previous) || unicode.IsDigit(previous)) {
			b.WriteRune(' ')
		}
		b.WriteRune(r)
		previous = r
	}
	return normalize(b.String())
}

func credentialInspectionContext(text string) bool {
	if hasAny(text, "secret scanning", "scan for secret", "scan secret", "detect secret") {
		return true
	}
	return hasAny(text, "scan", "scanning", "detect", "detection") && hasAny(text, "secret", "credential", "password", "api key", "token")
}
func firstMatch(text string, words []string) (string, bool) {
	normalizedText := normalize(text)
	tokens := strings.Fields(normalizedText)
	for _, word := range words {
		normalizedWord := normalize(word)
		if strings.Contains(normalizedWord, " ") {
			paddedText := " " + normalizedText + " "
			if strings.Contains(paddedText, " "+normalizedWord+" ") || strings.Contains(paddedText, " "+normalizedWord+"s ") || strings.Contains(paddedText, " "+normalizedWord+"es ") {
				return word, true
			}
		}
		for _, token := range tokens {
			if token == normalizedWord || token == normalizedWord+"s" || token == normalizedWord+"es" {
				return word, true
			}
		}
	}
	return "", false
}
func hasAny(text string, words ...string) bool { _, ok := firstMatch(text, words); return ok }
func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func intersect(values, wanted []string) []string {
	out := []string{}
	for _, value := range values {
		if contains(wanted, value) {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
func compact(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}
func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
func stringSet(v any) map[string]bool {
	out := map[string]bool{}
	if values, ok := v.([]any); ok {
		for _, value := range values {
			if s, ok := value.(string); ok {
				out[s] = true
			}
		}
	}
	if values, ok := v.([]string); ok {
		for _, value := range values {
			out[value] = true
		}
	}
	return out
}
func title(v string) string {
	parts := strings.Split(strings.ToLower(v), "_")
	for i := range parts {
		if parts[i] != "" {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, " ")
}
