package rules

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/agntid/observatory/api/internal/domain"
)

func TestPublicRulesAndScoring(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../../rules/public"))
	evaluator, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &domain.Assessment{Mode: "sample", Facts: map[string]any{
		"transport.https": true, "transport.hsts": false, "auth.anonymous": false,
		"authorization.assessed": true, "protocol.negotiated": true,
		"ai.missing_descriptions": 3, "ai.context_utilization": 18.8, "ai.tool_tokens": 18420,
		"operational.average_latency_ms": 187,
	}}
	findings, err := evaluator.Evaluate(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
	a.Findings = findings
	Score(a)
	if a.Scorecard.Overall < 80 || a.Scorecard.Overall > 99 {
		t.Fatalf("unexpected score %d", a.Scorecard.Overall)
	}
	if a.Scorecard.Coverage != 100 {
		t.Fatalf("unexpected coverage %.0f", a.Scorecard.Coverage)
	}
}

func TestFindingToolNamesAreNotSilentlyTruncated(t *testing.T) {
	tools := make([]domain.ToolProfile, 0, 20)
	for i := 0; i < 20; i++ {
		tools = append(tools, domain.ToolProfile{Name: fmt.Sprintf("tool_%02d", i), Schema: domain.SchemaAnalysis{Signals: []domain.SchemaSignal{{Code: "schema.output_missing"}}}})
	}
	names := findingToolNames(&domain.Assessment{Tools: tools}, "OBS-SCHEMA-001", nil)
	if len(names) != 20 {
		t.Fatalf("affected tools were truncated: got %d want 20", len(names))
	}
}

func TestFindingConfidenceAndPenaltyFollowUnderlyingEvidence(t *testing.T) {
	a := &domain.Assessment{
		Evidence: []domain.Evidence{{ID: "tool-intel", Observation: domain.Observation{Confidence: .65, Provenance: "inferred"}}},
		Tools:    []domain.ToolProfile{{Name: "risky_tool", Confidence: .8}},
	}
	confidence := findingConfidence(a, []string{"tool-intel"}, []string{"risky_tool"})
	if confidence != .65 {
		t.Fatalf("finding confidence = %.2f, want .65", confidence)
	}
	if penalty := effectivePenalty(14, confidence); penalty != 7 {
		t.Fatalf("effective penalty = %d, want 7", penalty)
	}
	if provenance := findingProvenance(a, []string{"tool-intel"}); provenance != "inferred" {
		t.Fatalf("finding provenance = %s, want inferred", provenance)
	}
}

func TestHighImpactRuleBuildsMetadataDerivedReplay(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../../rules/public"))
	evaluator, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	var highImpact domain.Rule
	for _, rule := range evaluator.Rules() {
		if rule.ID == "OBS-TOOLS-002" {
			highImpact = rule
			break
		}
	}
	if highImpact.Replay == nil || highImpact.Classification != "policy-opportunity" {
		t.Fatal("high-impact rule is missing replay or classification metadata")
	}
	a := &domain.Assessment{Tools: []domain.ToolProfile{{
		Name:           "delete_customer_records",
		Risk:           "critical",
		VisibleTo:      []string{"Writer", "Administrator"},
		Classification: domain.ToolClassification{OperationType: "DELETE", IsMutating: true, Effects: []string{"DESTRUCTIVE"}},
		PolicyPreview:  map[string]domain.ToolPolicyDecision{"protected": {Disposition: "approval", RequiresApproval: true}},
	}}}
	replay := buildReplay(a, highImpact)
	if replay == nil || !strings.Contains(replay.Observed, "delete_customer_records") {
		t.Fatalf("replay did not use the observed tool: %#v", replay)
	}
	if !strings.Contains(replay.AgntIDDecision, "require approval") {
		t.Fatalf("replay did not include the assessment policy preview: %q", replay.AgntIDDecision)
	}
	if !strings.Contains(replay.Disclaimer, "did not invoke a tool") {
		t.Fatalf("replay is missing the non-invocation disclaimer: %q", replay.Disclaimer)
	}
}

func TestDocumentationFindingNamesAffectedTools(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../../rules/public"))
	evaluator, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &domain.Assessment{
		Facts: map[string]any{"ai.missing_descriptions": 2},
		Tools: []domain.ToolProfile{
			{Name: "missing_one"},
			{Name: "described", Description: "A useful description."},
			{Name: "missing_two", Description: "   "},
		},
	}
	findings, err := evaluator.Evaluate(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.RuleID != "OBS-AI-001" {
			continue
		}
		if strings.Join(finding.ToolNames, ",") != "missing_one,missing_two" {
			t.Fatalf("documentation finding has incorrect tool links: %#v", finding.ToolNames)
		}
		return
	}
	t.Fatal("missing documentation finding")
}

func TestOWASPRulesNameObservedTrustBoundaries(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../../rules/public"))
	evaluator, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	openWorld := true
	a := &domain.Assessment{Facts: map[string]any{
		"input.unconstrained_sink_tool_count":   1,
		"input.credential_parameter_tool_count": 1,
		"output.open_world_untyped_tool_count":  1,
	}, Tools: []domain.ToolProfile{{
		Name: "fetch_external_page", Annotations: domain.ToolAnnotations{OpenWorldHint: &openWorld},
		Classification: domain.ToolClassification{Effects: []string{"NETWORK_EGRESS"}},
		Schema: domain.SchemaAnalysis{InputRisks: []domain.InputRisk{
			{Kind: "URL", Path: "$.target_url", Severity: "medium", Constrained: false},
			{Kind: "CREDENTIAL", Path: "$.access_token", Severity: "high", Constrained: false},
		}},
		PolicyPreview: map[string]domain.ToolPolicyDecision{"protected": {Disposition: "approval", RequiresApproval: true}},
	}}}
	findings, err := evaluator.Evaluate(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]string{
		"OBS-INPUT-001":      "$.target_url",
		"OBS-CREDENTIAL-001": "$.access_token",
		"OBS-OUTPUT-001":     "fetch_external_page",
	}
	for _, finding := range findings {
		expected, ok := wanted[finding.RuleID]
		if !ok {
			continue
		}
		if finding.Replay == nil || !strings.Contains(finding.Replay.Observed, expected) {
			t.Fatalf("%s replay missing observed boundary %q: %#v", finding.RuleID, expected, finding.Replay)
		}
		if len(finding.ToolNames) != 1 || finding.ToolNames[0] != "fetch_external_page" {
			t.Fatalf("%s finding is missing its related tool link: %#v", finding.RuleID, finding.ToolNames)
		}
		delete(wanted, finding.RuleID)
	}
	if len(wanted) != 0 {
		t.Fatalf("missing OWASP findings: %v", wanted)
	}
}

func TestUnreachableAssessmentScoresZero(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../../rules/public"))
	evaluator, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &domain.Assessment{Facts: map[string]any{"discovery.reachable": false, "authorization.assessed": false, "protocol.negotiated": false}}
	findings, err := evaluator.Evaluate(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	a.Findings = findings
	Score(a)
	if a.Scorecard.Overall != 0 {
		t.Fatalf("unreachable target scored %d", a.Scorecard.Overall)
	}
	found := false
	for _, finding := range findings {
		if finding.RuleID == "OBS-DISCOVERY-001" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing unreachable-target finding")
	}
}

func TestOAuthPostureRulesDistinguishSecurityAndInteroperability(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../../rules/public"))
	evaluator, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &domain.Assessment{Facts: map[string]any{
		"oauth.detected": true, "oauth.resource_metadata_valid": true,
		"oauth.authorization_server_metadata_valid": true, "oauth.pkce_s256": true,
		"oauth.dcr_supported": false, "oauth.client_id_metadata_document_supported": false,
		"oauth.unsafe_bearer_methods": true, "oauth.scopes_advertised": false,
	}}
	findings, err := evaluator.Evaluate(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{"OBS-OAUTH-004": false, "OBS-OAUTH-005": false, "OBS-OAUTH-006": false}
	for _, finding := range findings {
		if _, ok := wanted[finding.RuleID]; ok {
			wanted[finding.RuleID] = true
		}
	}
	for id, found := range wanted {
		if !found {
			t.Fatalf("missing OAuth finding %s in %#v", id, findings)
		}
	}
}
