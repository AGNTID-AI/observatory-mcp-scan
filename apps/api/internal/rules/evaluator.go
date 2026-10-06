package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/agntid/observatory/api/internal/domain"
	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"gopkg.in/yaml.v3"
)

type Evaluator struct{ rules []domain.Rule }

func Load(dir string) (*Evaluator, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	loaded := []domain.Rule{}
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml")) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var rule domain.Rule
		if err := yaml.Unmarshal(b, &rule); err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		base := strings.TrimSuffix(strings.TrimSuffix(entry.Name(), ".yaml"), ".yml")
		regoBytes, err := os.ReadFile(filepath.Join(dir, base+".rego"))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", base, err)
		}
		rule.Rego = string(regoBytes)
		if rule.Module == "" {
			rule.Module = "public"
		}
		if rule.Classification == "" {
			rule.Classification = classifyRule(rule.Category)
		}
		loaded = append(loaded, rule)
	}
	sort.Slice(loaded, func(i, j int) bool { return loaded[i].ID < loaded[j].ID })
	return &Evaluator{rules: loaded}, nil
}
func (e *Evaluator) Rules() []domain.Rule { return append([]domain.Rule(nil), e.rules...) }

func (e *Evaluator) Evaluate(ctx context.Context, a *domain.Assessment) ([]domain.Finding, error) {
	inputBytes, _ := json.Marshal(a)
	var input any
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		return nil, err
	}
	findings := []domain.Finding{}
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}
		rs, err := rego.New(rego.Query(rule.Query), rego.Module(rule.ID+".rego", rule.Rego), rego.Input(input), rego.SetRegoVersion(ast.RegoV1)).Eval(ctx)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		matched := false
		for _, r := range rs {
			for _, ex := range r.Expressions {
				if b, ok := ex.Value.(bool); ok && b {
					matched = true
				}
			}
		}
		if !matched {
			continue
		}
		rec := domain.Recommendation{ID: "rec-" + strings.ToLower(rule.ID), Priority: rule.Severity, Title: rule.Title, Detail: rule.Recommendation, Effort: effort(rule.Severity)}
		replay := buildReplay(a, rule)
		evidenceIDs := matchEvidence(a, rule.Evidence)
		toolNames := findingToolNames(a, rule.ID, replay)
		confidence := findingConfidence(a, evidenceIDs, toolNames)
		findings = append(findings, domain.Finding{ID: uuid.NewString(), RuleID: rule.ID, Category: rule.Category, Severity: rule.Severity, Title: rule.Title, Description: rule.Description, WhyItMatters: rule.WhyItMatters, Recommendation: rec, EvidenceIDs: evidenceIDs, Confidence: confidence, Provenance: findingProvenance(a, evidenceIDs), Penalty: effectivePenalty(rule.Penalty, confidence), Dimension: rule.Dimension, References: rule.References, Classification: rule.Classification, ToolNames: toolNames, Replay: replay})
	}
	return findings, nil
}

func findingToolNames(a *domain.Assessment, ruleID string, replay *domain.PolicyReplay) []string {
	if replay != nil && len(replay.ToolNames) > 0 {
		return compactStrings(replay.ToolNames)
	}
	names := []string{}
	switch ruleID {
	case "OBS-AI-001":
		for _, tool := range a.Tools {
			if strings.TrimSpace(tool.Description) == "" {
				names = append(names, tool.Name)
			}
		}
	case "OBS-SCHEMA-001":
		for _, tool := range a.Tools {
			if len(tool.Schema.Signals) > 0 {
				names = append(names, tool.Name)
			}
		}
	case "OBS-READINESS-001":
		for _, tool := range a.Readiness.Tools {
			if tool.Score < 70 {
				names = append(names, tool.ToolName)
			}
		}
	case "OBS-DRIFT-001", "OBS-DRIFT-002":
		for _, change := range a.CatalogDrift.Changes {
			names = append(names, change.ToolName)
		}
	case "OBS-CONTENT-001", "OBS-CONTENT-002":
		for _, signal := range a.ContentIntegrity.Signals {
			if signal.SurfaceKind == "tool" || signal.SurfaceKind == "schema" {
				names = append(names, signal.SurfaceID)
			}
		}
	}
	return compactStrings(names)
}

func classifyRule(category string) string {
	switch strings.ToLower(category) {
	case "policy opportunity":
		return "policy-opportunity"
	case "capability exposure", "authorization exposure":
		return "exposure"
	case "capability chain":
		return "capability-chain"
	case "metadata integrity", "tool integrity":
		return "integrity"
	case "catalog governance":
		return "governance"
	case "tool contract readiness", "schema safety", "documentation quality", "context efficiency":
		return "readiness"
	case "input boundary":
		return "input-boundary"
	case "credential boundary":
		return "credential-boundary"
	case "output trust boundary":
		return "output-boundary"
	default:
		return "posture"
	}
}

func buildReplay(a *domain.Assessment, rule domain.Rule) *domain.PolicyReplay {
	if rule.Replay == nil {
		return nil
	}
	observed, toolNames := replayObservation(a, rule.ID)
	decision := rule.Replay.AgntIDDecision
	if preview := protectedPreview(a, toolNames); preview != "" {
		decision += " Current metadata-derived preview: " + preview
	}
	return &domain.PolicyReplay{
		Title: rule.Replay.Title, Observed: observed, Trigger: rule.Replay.Trigger,
		UnprotectedPath: rule.Replay.UnprotectedPath, AgntIDDecision: decision,
		ProtectedOutcome: rule.Replay.ProtectedOutcome, ToolNames: toolNames,
		Disclaimer: "Illustrative policy replay derived from advertised metadata. Observatory did not invoke a tool, test the target's enforcement, or observe this sequence occurring.",
	}
}

func replayObservation(a *domain.Assessment, ruleID string) (string, []string) {
	tools := []domain.ToolProfile{}
	switch ruleID {
	case "OBS-TOOLS-001":
		for _, tool := range a.Tools {
			if len(tool.Classification.AnnotationContradictions) > 0 {
				tools = append(tools, tool)
			}
		}
	case "OBS-TOOLS-002":
		for _, tool := range a.Tools {
			if tool.Classification.IsMutating && (contains(tool.Classification.Effects, "DESTRUCTIVE") || strings.EqualFold(tool.Risk, "high") || strings.EqualFold(tool.Risk, "critical")) {
				tools = append(tools, tool)
			}
		}
	case "OBS-EXPOSURE-001":
		for _, tool := range a.Tools {
			if contains(tool.VisibleTo, "Anonymous") && contains(tool.Classification.Effects, "DESTRUCTIVE") {
				tools = append(tools, tool)
			}
		}
	case "OBS-CHAIN-001":
		if len(a.RiskChains) > 0 {
			names := compactStrings(a.RiskChains[0].ToolNames)
			examples := limited(names, 4)
			suffix := ""
			if len(names) > len(examples) {
				suffix = fmt.Sprintf(" and %d more", len(names)-len(examples))
			}
			return fmt.Sprintf("The catalog exposes the ingredients for '%s' across %s%s.", a.RiskChains[0].Title, strings.Join(examples, ", "), suffix), names
		}
	case "OBS-AUTHZ-001":
		labels := []string{}
		for _, profile := range a.IdentityExposure.Profiles {
			if profile.Status == "connected" {
				labels = append(labels, profile.Label)
			}
		}
		return fmt.Sprintf("%d measured identities (%s) received equivalent advertised catalogs.", a.IdentityExposure.ComparedProfiles, strings.Join(labels, ", ")), []string{}
	case "OBS-INPUT-001":
		return inputRiskObservation(a, false)
	case "OBS-CREDENTIAL-001":
		return inputRiskObservation(a, true)
	case "OBS-OUTPUT-001":
		return outputRiskObservation(a)
	}
	if len(tools) == 0 {
		return "The rule matched the normalized assessment facts; no single tool example was available.", []string{}
	}
	tools = tools[:min(len(tools), 3)]
	names, examples := []string{}, []string{}
	for _, tool := range tools {
		names = append(names, tool.Name)
		detail := strings.ToLower(strings.Trim(strings.Join([]string{tool.Classification.OperationType, tool.Risk}, " / "), " /"))
		if len(tool.VisibleTo) > 0 {
			detail += ", visible to " + strings.Join(tool.VisibleTo, ", ")
		}
		examples = append(examples, fmt.Sprintf("%s (%s)", tool.Name, detail))
	}
	return "Observed example: " + strings.Join(examples, "; ") + ".", names
}

func inputRiskObservation(a *domain.Assessment, credentials bool) (string, []string) {
	examples, names := []string{}, []string{}
	for _, tool := range a.Tools {
		for _, risk := range tool.Schema.InputRisks {
			matches := risk.Kind == "CREDENTIAL"
			if matches != credentials || (!credentials && risk.Constrained) {
				continue
			}
			label := strings.ToLower(strings.ReplaceAll(risk.Kind, "_", " "))
			if credentials {
				label = "model-visible credential field"
			} else {
				label += ", no declared format/pattern/enum"
			}
			names = append(names, tool.Name)
			if len(examples) < 4 {
				examples = append(examples, fmt.Sprintf("%s %s (%s)", tool.Name, risk.Path, label))
			}
		}
	}
	if len(examples) == 0 {
		return "The rule matched normalized tool-intelligence facts; no individual field was available.", []string{}
	}
	return "Observed schema fields: " + strings.Join(examples, "; ") + ".", compactStrings(names)
}

func outputRiskObservation(a *domain.Assessment) (string, []string) {
	examples, names := []string{}, []string{}
	for _, tool := range a.Tools {
		if tool.Schema.HasOutputSchema || !openWorldTool(tool) {
			continue
		}
		names = append(names, tool.Name)
		if len(examples) < 4 {
			examples = append(examples, tool.Name+" (remote or open-world result; no output schema advertised)")
		}
	}
	if len(examples) == 0 {
		return "The rule matched normalized tool-intelligence facts; no individual tool was available.", []string{}
	}
	return "Observed output trust boundaries: " + strings.Join(examples, "; ") + ".", compactStrings(names)
}

func openWorldTool(tool domain.ToolProfile) bool {
	return (tool.Annotations.OpenWorldHint != nil && *tool.Annotations.OpenWorldHint) || (tool.Classification.IsDiscover && tool.Classification.ExecutionSurface == "REMOTE_API") || contains(tool.Classification.Effects, "EXTERNAL_SERVICE_CALL") || tool.Classification.ExecutionSurface == "BROWSER_SESSION"
}

func compactStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func protectedPreview(a *domain.Assessment, names []string) string {
	decisions := []string{}
	for _, name := range names {
		for _, tool := range a.Tools {
			if tool.Name != name {
				continue
			}
			if decision, ok := tool.PolicyPreview["protected"]; ok {
				label := decision.Disposition
				if decision.RequiresApproval {
					label = "require approval"
				}
				decisions = append(decisions, name+" → "+label)
			}
		}
	}
	return strings.Join(decisions, "; ")
}

func limited(values []string, n int) []string {
	if len(values) <= n {
		return append([]string(nil), values...)
	}
	return append([]string(nil), values[:n]...)
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func matchEvidence(a *domain.Assessment, kinds []string) []string {
	ids := []string{}
	for _, e := range a.Evidence {
		for _, kind := range kinds {
			if e.Kind == kind || e.Observation.Source == kind {
				ids = append(ids, e.ID)
				break
			}
		}
	}
	return ids
}
func findingConfidence(a *domain.Assessment, evidenceIDs, toolNames []string) float64 {
	values := []float64{}
	for _, id := range evidenceIDs {
		for _, evidence := range a.Evidence {
			if evidence.ID == id && evidence.Observation.Confidence > 0 {
				values = append(values, evidence.Observation.Confidence)
			}
		}
	}
	for _, name := range toolNames {
		for _, tool := range a.Tools {
			if tool.Name == name && tool.Confidence > 0 {
				values = append(values, tool.Confidence)
			}
		}
	}
	if len(values) == 0 {
		if a.Mode == "sample" {
			return .6
		}
		return .65
	}
	minimum := values[0]
	for _, value := range values[1:] {
		if value < minimum {
			minimum = value
		}
	}
	return minimum
}

func findingProvenance(a *domain.Assessment, evidenceIDs []string) string {
	if a.Mode == "sample" {
		return "sample"
	}
	rank := map[string]int{"measured": 4, "sampled": 3, "imported": 3, "inferred": 2, "unavailable": 1}
	result := "measured"
	lowest := rank[result]
	for _, id := range evidenceIDs {
		for _, evidence := range a.Evidence {
			if evidence.ID != id {
				continue
			}
			value := evidence.Observation.Provenance
			if current, ok := rank[value]; ok && current < lowest {
				result, lowest = value, current
			}
		}
	}
	if len(evidenceIDs) == 0 {
		return "inferred"
	}
	return result
}

func effectivePenalty(base int, confidence float64) int {
	if base <= 0 {
		return 0
	}
	factor := 0.0
	switch {
	case confidence >= .85:
		factor = 1
	case confidence >= .7:
		factor = .75
	case confidence >= .55:
		factor = .5
	}
	return int(float64(base)*factor + .5)
}
func effort(sev string) string {
	switch sev {
	case "critical", "high":
		return "medium"
	case "medium":
		return "low"
	default:
		return "low"
	}
}

func Score(a *domain.Assessment) {
	weights := map[string]int{"security": 35, "protocol": 20, "ai-readiness": 25, "operational": 20}
	coverage := map[string]float64{"security": 100, "protocol": 100, "ai-readiness": 100, "operational": 100}
	if value, ok := a.Facts["authorization.assessed"]; !ok || value != true {
		coverage["security"] -= 15
	}
	if value, ok := a.Facts["protocol.negotiated"]; !ok || value != true {
		coverage["protocol"] -= 40
	}
	if _, ok := a.Facts["ai.tool_tokens"]; !ok {
		coverage["ai-readiness"] = 0
	}
	if _, ok := a.Facts["operational.average_latency_ms"]; !ok {
		coverage["operational"] = 0
	}
	if a.Mode == "offline" {
		// Offline assessments can deeply evaluate declarations, but cannot
		// measure network, identity enforcement, protocol negotiation, or
		// operations. Keep those gaps visible instead of rewarding absence.
		coverage["security"] = 45
		coverage["protocol"] = 0
		if declared, ok := a.Facts["protocol.declared"]; ok && declared == true {
			coverage["protocol"] = 25
		}
		coverage["operational"] = 0
	}
	scores := map[string]int{"security": 100, "protocol": 100, "ai-readiness": 100, "operational": 100}
	a.Risk = domain.RiskProfile{}
	for _, f := range a.Findings {
		if _, ok := scores[f.Dimension]; ok {
			scores[f.Dimension] -= f.Penalty
			if scores[f.Dimension] < 0 {
				scores[f.Dimension] = 0
			}
		}
		switch f.Severity {
		case "critical":
			a.Risk.Critical++
		case "high":
			a.Risk.High++
		case "medium":
			a.Risk.Medium++
		case "low":
			a.Risk.Low++
		default:
			a.Risk.Info++
		}
	}
	if established, observed := a.Facts["discovery.session_established"]; (observed && established == false) || (!observed && a.Facts["discovery.reachable"] == false) {
		for key := range scores {
			scores[key] = 0
		}
		coverage["ai-readiness"] = 0
		coverage["operational"] = 100
	}
	dims := map[string]domain.DimensionScore{}
	weighted := 0.0
	denom := 0.0
	totalCoverage := 0.0
	for id, w := range weights {
		status := "assessed"
		if coverage[id] == 0 {
			status = "not-assessed"
		} else if coverage[id] < 100 {
			status = "partial"
		}
		dims[id] = domain.DimensionScore{Name: display(id), Score: scores[id], Coverage: coverage[id], Status: status, Weight: w}
		if coverage[id] > 0 {
			effective := float64(w) * coverage[id] / 100
			weighted += float64(scores[id]) * effective
			denom += effective
		}
		totalCoverage += float64(w) * coverage[id] / 100
	}
	overall := 0
	if denom > 0 {
		overall = int(mathRound(weighted / denom))
	}
	a.Scorecard = domain.Scorecard{Overall: overall, Coverage: totalCoverage, Dimensions: dims}
}
func display(v string) string {
	switch v {
	case "ai-readiness":
		return "AI Readiness"
	case "security":
		return "Security"
	case "protocol":
		return "Protocol"
	case "operational":
		return "Operational"
	}
	return v
}
func mathRound(v float64) float64 {
	if v < 0 {
		return float64(int(v - .5))
	}
	return float64(int(v + .5))
}
