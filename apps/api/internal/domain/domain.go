package domain

import (
	"encoding/json"
	"time"
)

type AssessmentStatus string

const (
	StatusQueued    AssessmentStatus = "queued"
	StatusRunning   AssessmentStatus = "running"
	StatusCompleted AssessmentStatus = "completed"
	StatusPartial   AssessmentStatus = "partial"
	StatusFailed    AssessmentStatus = "failed"
	StatusCanceled  AssessmentStatus = "canceled"
)

type Target struct {
	Protocol string `json:"protocol"`
	URL      string `json:"url"`
	Host     string `json:"host,omitempty"`
}

type Observation struct {
	Source      string    `json:"source"`
	Confidence  float64   `json:"confidence"`
	Provenance  string    `json:"provenance"`
	CollectedAt time.Time `json:"collectedAt"`
}

type EngineRun struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Status      string     `json:"status"`
	Progress    int        `json:"progress"`
	Message     string     `json:"message,omitempty"`
	StartedAt   *time.Time `json:"startedAt,omitempty"`
	CompletedAt *time.Time `json:"completedAt,omitempty"`
	DurationMs  int64      `json:"durationMs,omitempty"`
}

type Evidence struct {
	ID          string         `json:"id"`
	Kind        string         `json:"kind"`
	Title       string         `json:"title"`
	Summary     string         `json:"summary"`
	Data        map[string]any `json:"data,omitempty"`
	Observation Observation    `json:"observation"`
}

type Recommendation struct {
	ID       string `json:"id"`
	Priority string `json:"priority"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Effort   string `json:"effort,omitempty"`
}

// RuleReplay is authored with a rule and describes a safe, illustrative
// sequence. It never instructs Observatory to invoke a target capability.
type RuleReplay struct {
	Title            string `json:"title" yaml:"title"`
	Trigger          string `json:"trigger" yaml:"trigger"`
	UnprotectedPath  string `json:"unprotectedPath" yaml:"unprotected_path"`
	AgntIDDecision   string `json:"agntidDecision" yaml:"agntid_decision"`
	ProtectedOutcome string `json:"protectedOutcome" yaml:"protected_outcome"`
}

type PolicyReplay struct {
	Title            string   `json:"title"`
	Observed         string   `json:"observed"`
	Trigger          string   `json:"trigger"`
	UnprotectedPath  string   `json:"unprotectedPath"`
	AgntIDDecision   string   `json:"agntidDecision"`
	ProtectedOutcome string   `json:"protectedOutcome"`
	ToolNames        []string `json:"toolNames"`
	Disclaimer       string   `json:"disclaimer"`
}

type Finding struct {
	ID             string         `json:"id"`
	RuleID         string         `json:"ruleId"`
	Category       string         `json:"category"`
	Severity       string         `json:"severity"`
	Title          string         `json:"title"`
	Description    string         `json:"description"`
	WhyItMatters   string         `json:"whyItMatters"`
	Recommendation Recommendation `json:"recommendation"`
	EvidenceIDs    []string       `json:"evidenceIds"`
	Confidence     float64        `json:"confidence"`
	Provenance     string         `json:"provenance"`
	Penalty        int            `json:"penalty"`
	Dimension      string         `json:"dimension"`
	References     []string       `json:"references,omitempty"`
	Classification string         `json:"classification"`
	ToolNames      []string       `json:"toolNames"`
	Replay         *PolicyReplay  `json:"replay,omitempty"`
}

type ToolAnnotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    *bool  `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool  `json:"destructiveHint,omitempty"`
	IdempotentHint  *bool  `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool  `json:"openWorldHint,omitempty"`
}

type DimensionConfidence struct {
	Band     string   `json:"band"`
	Score    float64  `json:"score"`
	Evidence []string `json:"evidence"`
}

type ToolClassification struct {
	TaxonomyVersion          int                            `json:"taxonomyVersion"`
	ClassifierRevision       string                         `json:"classifierRevision"`
	OperationType            string                         `json:"operationType"`
	Domain                   string                         `json:"domain"`
	BlastRadius              string                         `json:"blastRadius"`
	Sensitivity              string                         `json:"sensitivity"`
	Criticality              string                         `json:"criticality"`
	PrivilegeLevel           int                            `json:"privilegeLevel"`
	IsMutating               bool                           `json:"isMutating"`
	IsDiscover               bool                           `json:"isDiscover"`
	ExecutionSurface         string                         `json:"executionSurface"`
	Effects                  []string                       `json:"effects"`
	ConfidenceBand           string                         `json:"confidenceBand"`
	PerDimensionConfidence   map[string]DimensionConfidence `json:"perDimensionConfidence"`
	Evidence                 []string                       `json:"evidence"`
	AnnotationContradictions []string                       `json:"annotationContradictions"`
}

type SchemaSignal struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Path     string `json:"path,omitempty"`
	Message  string `json:"message"`
}

type InputRisk struct {
	Kind        string `json:"kind"`
	Path        string `json:"path"`
	Severity    string `json:"severity"`
	Reason      string `json:"reason"`
	Constrained bool   `json:"constrained"`
}

type SchemaAnalysis struct {
	Valid                    bool           `json:"valid"`
	HasOutputSchema          bool           `json:"hasOutputSchema"`
	AdditionalProperties     string         `json:"additionalProperties"`
	PropertyCount            int            `json:"propertyCount"`
	RequiredCount            int            `json:"requiredCount"`
	DescribedPropertyCount   int            `json:"describedPropertyCount"`
	DescriptionCoverage      float64        `json:"descriptionCoverage"`
	MaxDepth                 int            `json:"maxDepth"`
	UnconstrainedStringCount int            `json:"unconstrainedStringCount"`
	SensitiveFields          []string       `json:"sensitiveFields"`
	DangerousFields          []string       `json:"dangerousFields"`
	InputRisks               []InputRisk    `json:"inputRisks"`
	Signals                  []SchemaSignal `json:"signals"`
}

type ToolPolicyDecision struct {
	Profile          string   `json:"profile"`
	Disposition      string   `json:"disposition"`
	Reasons          []string `json:"reasons"`
	RequiresApproval bool     `json:"requiresApproval"`
}

type ToolProfile struct {
	Name            string                        `json:"name"`
	Description     string                        `json:"description,omitempty"`
	InputSchema     map[string]any                `json:"inputSchema,omitempty"`
	OutputSchema    map[string]any                `json:"outputSchema,omitempty"`
	Annotations     ToolAnnotations               `json:"annotations"`
	Categories      []string                      `json:"categories"`
	Risk            string                        `json:"risk"`
	Confidence      float64                       `json:"confidence"`
	EstimatedTokens int                           `json:"estimatedTokens"`
	Fingerprint     string                        `json:"fingerprint"`
	VisibleTo       []string                      `json:"visibleTo"`
	Classification  ToolClassification            `json:"classification"`
	Schema          SchemaAnalysis                `json:"schema"`
	PolicyPreview   map[string]ToolPolicyDecision `json:"policyPreview"`
}

type IdentityProfile struct {
	ID                 string   `json:"id"`
	Label              string   `json:"label"`
	Kind               string   `json:"kind"`
	Status             string   `json:"status"`
	Authentication     string   `json:"authentication"`
	ToolCount          int      `json:"toolCount"`
	ToolNames          []string `json:"toolNames"`
	CatalogFingerprint string   `json:"catalogFingerprint,omitempty"`
	Error              string   `json:"error,omitempty"`
}

type ToolExposure struct {
	ToolName          string   `json:"toolName"`
	VisibleTo         []string `json:"visibleTo"`
	HiddenFrom        []string `json:"hiddenFrom"`
	CatalogEquivalent bool     `json:"catalogEquivalent"`
}

type IdentityExposure struct {
	Profiles                    []IdentityProfile `json:"profiles"`
	Tools                       []ToolExposure    `json:"tools"`
	ComparedProfiles            int               `json:"comparedProfiles"`
	CatalogEquivalent           bool              `json:"catalogEquivalent"`
	PrivilegeSeparationObserved bool              `json:"privilegeSeparationObserved"`
	AnonymousToolCount          int               `json:"anonymousToolCount"`
	Notes                       []string          `json:"notes"`
}

type PolicySimulationProfile struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	VisibleCount     int      `json:"visibleCount"`
	HiddenCount      int      `json:"hiddenCount"`
	ApprovalCount    int      `json:"approvalCount"`
	VisibleToolNames []string `json:"visibleToolNames"`
	HiddenToolNames  []string `json:"hiddenToolNames"`
}

type PolicySimulation struct {
	Profiles   []PolicySimulationProfile `json:"profiles"`
	Generated  bool                      `json:"generated"`
	Disclaimer string                    `json:"disclaimer"`
}

type RiskChain struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	ToolNames   []string `json:"toolNames"`
	Signals     []string `json:"signals"`
}

// ContentItem is protocol-neutral metadata that may influence an agent before
// any action is executed (for example server instructions or tool/prompt text).
type ContentItem struct {
	Kind       string `json:"kind"`
	ID         string `json:"id"`
	Name       string `json:"name,omitempty"`
	Text       string `json:"text,omitempty"`
	URI        string `json:"uri,omitempty"`
	MIMEType   string `json:"mimeType,omitempty"`
	Provenance string `json:"provenance"`
}

type ContentSignal struct {
	ID             string   `json:"id"`
	RuleID         string   `json:"ruleId"`
	SurfaceKind    string   `json:"surfaceKind"`
	SurfaceID      string   `json:"surfaceId"`
	Severity       string   `json:"severity"`
	Category       string   `json:"category"`
	Title          string   `json:"title"`
	Summary        string   `json:"summary"`
	MatchedText    string   `json:"matchedText,omitempty"`
	Recommendation string   `json:"recommendation"`
	Confidence     float64  `json:"confidence"`
	Evidence       []string `json:"evidence"`
}

type ContentIntegrityProfile struct {
	ItemsScanned int             `json:"itemsScanned"`
	Signals      []ContentSignal `json:"signals"`
	BySeverity   map[string]int  `json:"bySeverity"`
	Disclaimer   string          `json:"disclaimer"`
}

type ReadinessCheck struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	Severity       string `json:"severity"`
	Status         string `json:"status"`
	Evidence       string `json:"evidence"`
	Recommendation string `json:"recommendation,omitempty"`
}

type ToolReadiness struct {
	ToolName string           `json:"toolName"`
	Score    int              `json:"score"`
	Coverage float64          `json:"coverage"`
	Grade    string           `json:"grade"`
	Checks   []ReadinessCheck `json:"checks"`
}

type ReadinessProfile struct {
	Tools        []ToolReadiness `json:"tools"`
	AverageScore int             `json:"averageScore"`
	Coverage     float64         `json:"coverage"`
	Disclaimer   string          `json:"disclaimer"`
}

type CatalogChange struct {
	ToolName            string   `json:"toolName"`
	ChangeType          string   `json:"changeType"`
	Severity            string   `json:"severity"`
	Summary             string   `json:"summary"`
	PolicyImpact        string   `json:"policyImpact"`
	Fields              []string `json:"fields"`
	PreviousFingerprint string   `json:"previousFingerprint,omitempty"`
	CurrentFingerprint  string   `json:"currentFingerprint,omitempty"`
}

type CatalogDriftProfile struct {
	BaselineAssessmentID string          `json:"baselineAssessmentId,omitempty"`
	BaselineAt           *time.Time      `json:"baselineAt,omitempty"`
	Compared             bool            `json:"compared"`
	Stable               bool            `json:"stable"`
	PreviousFingerprint  string          `json:"previousFingerprint,omitempty"`
	CurrentFingerprint   string          `json:"currentFingerprint,omitempty"`
	Added                int             `json:"added"`
	Removed              int             `json:"removed"`
	Modified             int             `json:"modified"`
	Changes              []CatalogChange `json:"changes"`
	Disclaimer           string          `json:"disclaimer"`
}

// OAuthPosture records public OAuth discovery metadata and the controls that
// Observatory could verify without invoking an MCP tool. Endpoint URLs and
// scopes are public protocol metadata; credentials and tokens never belong in
// this model.
type OAuthPosture struct {
	Status                            string    `json:"status"`
	Protected                         bool      `json:"protected"`
	ChallengePresent                  bool      `json:"challengePresent"`
	ResourceMetadataURL               string    `json:"resourceMetadataUrl,omitempty"`
	ResourceMetadataValid             bool      `json:"resourceMetadataValid"`
	Resource                          string    `json:"resource,omitempty"`
	AuthorizationServers              []string  `json:"authorizationServers"`
	AuthorizationServerMetadataValid  bool      `json:"authorizationServerMetadataValid"`
	Issuer                            string    `json:"issuer,omitempty"`
	AuthorizationEndpoint             string    `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint                     string    `json:"tokenEndpoint,omitempty"`
	RegistrationEndpoint              string    `json:"registrationEndpoint,omitempty"`
	DCRSupported                      bool      `json:"dcrSupported"`
	ClientIDMetadataDocumentSupported bool      `json:"clientIdMetadataDocumentSupported"`
	PKCES256                          bool      `json:"pkceS256"`
	Scopes                            []string  `json:"scopes"`
	BearerMethods                     []string  `json:"bearerMethods"`
	HeaderBearerSupported             bool      `json:"headerBearerSupported"`
	AuthorizationCompleted            bool      `json:"authorizationCompleted"`
	RegistrationMethod                string    `json:"registrationMethod,omitempty"`
	AuthorizedIdentities              []string  `json:"authorizedIdentities"`
	Diagnostics                       []string  `json:"diagnostics"`
	AssessedAt                        time.Time `json:"assessedAt,omitempty"`
}

// OfflineSnapshot is the portable declaration format accepted by the API and
// CI. It deliberately contains metadata only and cannot request tool execution.
type OfflineSnapshot struct {
	Name               string        `json:"name"`
	TargetURL          string        `json:"targetUrl,omitempty"`
	ServerInstructions string        `json:"serverInstructions,omitempty"`
	Server             ServerProfile `json:"server"`
	Tools              []ToolProfile `json:"tools"`
	Prompts            []ContentItem `json:"prompts,omitempty"`
	Resources          []ContentItem `json:"resources,omitempty"`
}

type ServerProfile struct {
	Name            string         `json:"name,omitempty"`
	Version         string         `json:"version,omitempty"`
	ProtocolVersion string         `json:"protocolVersion,omitempty"`
	Transport       string         `json:"transport,omitempty"`
	Capabilities    map[string]any `json:"capabilities,omitempty"`
	Authentication  string         `json:"authentication"`
	Authorization   string         `json:"authorization"`
	TLS             string         `json:"tls"`
	ToolCount       int            `json:"toolCount"`
	PromptCount     int            `json:"promptCount"`
	ResourceCount   int            `json:"resourceCount"`
}

type ContextProfile struct {
	ToolTokens        int     `json:"toolTokens"`
	PromptTokens      int     `json:"promptTokens"`
	ResourceTokens    int     `json:"resourceTokens"`
	InstructionTokens int     `json:"instructionTokens"`
	TotalTokens       int     `json:"totalTokens"`
	ContextWindow     int     `json:"contextWindow"`
	Utilization       float64 `json:"utilization"`
	Estimator         string  `json:"estimator"`
}

type RiskProfile struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type DimensionScore struct {
	Name     string  `json:"name"`
	Score    int     `json:"score"`
	Coverage float64 `json:"coverage"`
	Status   string  `json:"status"`
	Weight   int     `json:"weight"`
}

type Scorecard struct {
	Overall    int                       `json:"overall"`
	Coverage   float64                   `json:"coverage"`
	Dimensions map[string]DimensionScore `json:"dimensions"`
}

type Artifact struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Format      string    `json:"format"`
	Kind        string    `json:"kind"`
	ContentType string    `json:"contentType"`
	Size        int64     `json:"size"`
	SHA256      string    `json:"sha256"`
	CreatedAt   time.Time `json:"createdAt"`
}

type Assessment struct {
	ID               string                  `json:"id"`
	Mode             string                  `json:"mode"`
	Target           Target                  `json:"target"`
	Status           AssessmentStatus        `json:"status"`
	ConnectionStatus string                  `json:"connectionStatus"`
	Progress         int                     `json:"progress"`
	CurrentStage     string                  `json:"currentStage,omitempty"`
	ExecutiveSummary string                  `json:"executiveSummary,omitempty"`
	TechnicalSummary string                  `json:"technicalSummary,omitempty"`
	CreatedAt        time.Time               `json:"createdAt"`
	StartedAt        *time.Time              `json:"startedAt,omitempty"`
	CompletedAt      *time.Time              `json:"completedAt,omitempty"`
	EngineRuns       []EngineRun             `json:"engineRuns"`
	Findings         []Finding               `json:"findings"`
	Evidence         []Evidence              `json:"evidence"`
	Recommendations  []Recommendation        `json:"recommendations"`
	Artifacts        []Artifact              `json:"artifacts"`
	Tools            []ToolProfile           `json:"tools"`
	IdentityExposure IdentityExposure        `json:"identityExposure"`
	PolicySimulation PolicySimulation        `json:"policySimulation"`
	RiskChains       []RiskChain             `json:"riskChains"`
	ContentInventory []ContentItem           `json:"contentInventory"`
	ContentIntegrity ContentIntegrityProfile `json:"contentIntegrity"`
	Readiness        ReadinessProfile        `json:"readiness"`
	CatalogDrift     CatalogDriftProfile     `json:"catalogDrift"`
	OAuth            OAuthPosture            `json:"oauth"`
	Server           ServerProfile           `json:"server"`
	Context          ContextProfile          `json:"context"`
	Risk             RiskProfile             `json:"risk"`
	Scorecard        Scorecard               `json:"scorecard"`
	Facts            map[string]any          `json:"facts,omitempty"`
	Error            string                  `json:"error,omitempty"`
}

type AssessmentSummary struct {
	ID               string           `json:"id"`
	Mode             string           `json:"mode"`
	Target           Target           `json:"target"`
	Status           AssessmentStatus `json:"status"`
	ConnectionStatus string           `json:"connectionStatus"`
	Progress         int              `json:"progress"`
	OverallScore     int              `json:"overallScore"`
	Coverage         float64          `json:"coverage"`
	Risk             RiskProfile      `json:"risk"`
	CreatedAt        time.Time        `json:"createdAt"`
	CompletedAt      *time.Time       `json:"completedAt,omitempty"`
}

func (a Assessment) Summary() AssessmentSummary {
	return AssessmentSummary{ID: a.ID, Mode: a.Mode, Target: a.Target, Status: a.Status, ConnectionStatus: a.DeriveConnectionStatus(), Progress: a.Progress, OverallScore: a.Scorecard.Overall, Coverage: a.Scorecard.Coverage, Risk: a.Risk, CreatedAt: a.CreatedAt, CompletedAt: a.CompletedAt}
}

// DeriveConnectionStatus separates whether a live MCP session was established
// from whether the remaining diagnostic and reporting stages completed.
func (a Assessment) DeriveConnectionStatus() string {
	if a.Mode != "live" {
		return "not-applicable"
	}
	if established, ok := boolFact(a.Facts, "discovery.session_established"); ok {
		if established {
			return "connected"
		}
		if challenged, _ := boolFact(a.Facts, "auth.challenge_present"); challenged || numericFact(a.Facts, "auth.status_code") == 401 || numericFact(a.Facts, "auth.status_code") == 403 {
			return "authentication-required"
		}
		return "connection-failed"
	}
	if a.Status == StatusQueued || a.Status == StatusRunning {
		return "pending"
	}
	for _, profile := range a.IdentityExposure.Profiles {
		if profile.Status == "connected" {
			return "connected"
		}
	}
	if reachable, ok := boolFact(a.Facts, "discovery.reachable"); ok && !reachable {
		if challenged, _ := boolFact(a.Facts, "auth.challenge_present"); challenged || numericFact(a.Facts, "auth.status_code") == 401 || numericFact(a.Facts, "auth.status_code") == 403 {
			return "authentication-required"
		}
		return "connection-failed"
	}
	return "unknown"
}

func boolFact(facts map[string]any, key string) (bool, bool) {
	value, ok := facts[key]
	if !ok {
		return false, false
	}
	result, ok := value.(bool)
	return result, ok
}

func numericFact(facts map[string]any, key string) int {
	switch value := facts[key].(type) {
	case int:
		return value
	case float64:
		return int(value)
	default:
		return 0
	}
}

// Normalize keeps collection-valued API fields stable even for partial scans and
// assessments persisted by older releases.
func (a *Assessment) Normalize() {
	a.ConnectionStatus = a.DeriveConnectionStatus()
	if a.EngineRuns == nil {
		a.EngineRuns = []EngineRun{}
	}
	if a.Findings == nil {
		a.Findings = []Finding{}
	}
	for i := range a.Findings {
		if a.Findings[i].ToolNames == nil {
			if a.Findings[i].Replay != nil {
				a.Findings[i].ToolNames = append([]string(nil), a.Findings[i].Replay.ToolNames...)
			} else {
				a.Findings[i].ToolNames = []string{}
			}
		}
		if a.Findings[i].Replay != nil && a.Findings[i].Replay.ToolNames == nil {
			a.Findings[i].Replay.ToolNames = []string{}
		}
	}
	if a.Evidence == nil {
		a.Evidence = []Evidence{}
	}
	if a.Recommendations == nil {
		a.Recommendations = []Recommendation{}
	}
	if a.Artifacts == nil {
		a.Artifacts = []Artifact{}
	}
	if a.Tools == nil {
		a.Tools = []ToolProfile{}
	}
	if a.IdentityExposure.Profiles == nil {
		a.IdentityExposure.Profiles = []IdentityProfile{}
	}
	if a.IdentityExposure.Tools == nil {
		a.IdentityExposure.Tools = []ToolExposure{}
	}
	if a.IdentityExposure.Notes == nil {
		a.IdentityExposure.Notes = []string{}
	}
	if a.PolicySimulation.Profiles == nil {
		a.PolicySimulation.Profiles = []PolicySimulationProfile{}
	}
	if a.RiskChains == nil {
		a.RiskChains = []RiskChain{}
	}
	if a.ContentInventory == nil {
		a.ContentInventory = []ContentItem{}
	}
	if a.ContentIntegrity.Signals == nil {
		a.ContentIntegrity.Signals = []ContentSignal{}
	}
	if a.ContentIntegrity.BySeverity == nil {
		a.ContentIntegrity.BySeverity = map[string]int{}
	}
	if a.Readiness.Tools == nil {
		a.Readiness.Tools = []ToolReadiness{}
	}
	if a.CatalogDrift.Changes == nil {
		a.CatalogDrift.Changes = []CatalogChange{}
	}
	if a.OAuth.AuthorizationServers == nil {
		a.OAuth.AuthorizationServers = []string{}
	}
	if a.OAuth.Scopes == nil {
		a.OAuth.Scopes = []string{}
	}
	if a.OAuth.BearerMethods == nil {
		a.OAuth.BearerMethods = []string{}
	}
	if a.OAuth.AuthorizedIdentities == nil {
		a.OAuth.AuthorizedIdentities = []string{}
	}
	if a.OAuth.Diagnostics == nil {
		a.OAuth.Diagnostics = []string{}
	}
	for i := range a.Tools {
		if a.Tools[i].Categories == nil {
			a.Tools[i].Categories = []string{}
		}
		if a.Tools[i].VisibleTo == nil {
			a.Tools[i].VisibleTo = []string{}
		}
		if a.Tools[i].PolicyPreview == nil {
			a.Tools[i].PolicyPreview = map[string]ToolPolicyDecision{}
		}
		if a.Tools[i].Classification.Effects == nil {
			a.Tools[i].Classification.Effects = []string{}
		}
		if a.Tools[i].Classification.Evidence == nil {
			a.Tools[i].Classification.Evidence = []string{}
		}
		if a.Tools[i].Classification.AnnotationContradictions == nil {
			a.Tools[i].Classification.AnnotationContradictions = []string{}
		}
		if a.Tools[i].Classification.PerDimensionConfidence == nil {
			a.Tools[i].Classification.PerDimensionConfidence = map[string]DimensionConfidence{}
		}
		if a.Tools[i].Schema.Signals == nil {
			a.Tools[i].Schema.Signals = []SchemaSignal{}
		}
		if a.Tools[i].Schema.InputRisks == nil {
			a.Tools[i].Schema.InputRisks = []InputRisk{}
		}
	}
	if a.Facts == nil {
		a.Facts = map[string]any{}
	}
	if a.Server.Capabilities == nil {
		a.Server.Capabilities = map[string]any{}
	}
	if a.Scorecard.Dimensions == nil {
		a.Scorecard.Dimensions = map[string]DimensionScore{}
	}
}

type Event struct {
	ID           uint64          `json:"id"`
	AssessmentID string          `json:"assessmentId"`
	Type         string          `json:"type"`
	Data         json.RawMessage `json:"data"`
	CreatedAt    time.Time       `json:"createdAt"`
}

type Rule struct {
	ID             string      `json:"id" yaml:"id"`
	Version        string      `json:"version" yaml:"version"`
	Category       string      `json:"category" yaml:"category"`
	Severity       string      `json:"severity" yaml:"severity"`
	Dimension      string      `json:"dimension" yaml:"dimension"`
	Penalty        int         `json:"penalty" yaml:"penalty"`
	Title          string      `json:"title" yaml:"title"`
	Description    string      `json:"description" yaml:"description"`
	WhyItMatters   string      `json:"whyItMatters" yaml:"why_it_matters"`
	Recommendation string      `json:"recommendation" yaml:"recommendation"`
	References     []string    `json:"references" yaml:"references"`
	Tags           []string    `json:"tags" yaml:"tags"`
	Module         string      `json:"module" yaml:"module"`
	Query          string      `json:"query" yaml:"query"`
	Evidence       []string    `json:"evidence" yaml:"evidence"`
	Enabled        bool        `json:"enabled" yaml:"enabled"`
	Rego           string      `json:"rego,omitempty" yaml:"-"`
	Classification string      `json:"classification" yaml:"classification"`
	Replay         *RuleReplay `json:"replay,omitempty" yaml:"replay"`
}
