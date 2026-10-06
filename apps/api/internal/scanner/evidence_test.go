package scanner

import (
	"testing"

	"github.com/agntid/observatory/api/internal/domain"
	"github.com/agntid/observatory/api/internal/ports"
)

func TestEvidenceConfidenceReflectsProvenance(t *testing.T) {
	wanted := map[string]float64{
		"measured":    .95,
		"sampled":     .75,
		"inferred":    .65,
		"unavailable": 0,
	}
	for provenance, expected := range wanted {
		if actual := evidenceConfidence(provenance); actual != expected {
			t.Fatalf("%s evidence confidence = %.2f, want %.2f", provenance, actual, expected)
		}
	}
}

func TestRiskChainRequiresDistinctReadAndPublishingCapabilities(t *testing.T) {
	tools := []domain.ToolProfile{
		{Name: "search_code", Classification: domain.ToolClassification{OperationType: "LIST", Domain: "VCS", IsDiscover: true, ExecutionSurface: "REMOTE_API", Effects: []string{"READ"}}},
		{Name: "add_issue_comment", Classification: domain.ToolClassification{OperationType: "CREATE", IsMutating: true, Effects: []string{"NETWORK_EGRESS", "WRITE"}}},
	}
	chains := detectRiskChains(tools)
	if len(chains) != 1 {
		t.Fatalf("risk chain count = %d, want 1", len(chains))
	}
	if len(chains[0].ToolNames) != 2 {
		t.Fatalf("risk chain tools = %v, want both read and publishing capabilities", chains[0].ToolNames)
	}
}

func TestSingleConnectedIdentityLeavesAuthorizationNotAssessed(t *testing.T) {
	assessment := &domain.Assessment{
		Server: domain.ServerProfile{Authorization: "credential-unavailable"},
		IdentityExposure: domain.IdentityExposure{
			ComparedProfiles: 1,
			Profiles: []domain.IdentityProfile{
				{Label: "Anonymous", Kind: "anonymous", Status: "unavailable"},
				{Label: "Reader", Kind: "credential", Status: "connected"},
			},
		},
	}
	result := (StageEngine{StageID: "authorization"}).authorization(ports.EngineContext{Assessment: assessment})
	if result.Server == nil || result.Server.Authorization != "not-assessed" {
		t.Fatalf("authorization = %#v, want not-assessed", result.Server)
	}
	if assessed, _ := result.Facts["authorization.assessed"].(bool); assessed {
		t.Fatal("single catalog was treated as an authorization assessment")
	}
	if len(result.Evidence) != 1 || result.Evidence[0].Title != "Tool execution authorization was not assessed" {
		t.Fatalf("authorization evidence = %#v", result.Evidence)
	}
}
