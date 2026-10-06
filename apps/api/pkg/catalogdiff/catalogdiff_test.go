package catalogdiff

import (
	"strings"
	"testing"
)

func TestCompareHighlightsHighRiskAdditionAndSchemaChange(t *testing.T) {
	before := []Tool{{Name: "list", Description: "List", InputSchema: map[string]any{"type": "object"}}}
	after := []Tool{{Name: "list", Description: "List", InputSchema: map[string]any{"type": "object", "additionalProperties": false}}, {Name: "delete_all", Risk: "critical", OperationType: "DELETE"}}
	r := Compare(before, after)
	if r.Added != 1 || r.Modified != 1 {
		t.Fatalf("unexpected counts %#v", r)
	}
	if r.Changes[0].Severity != "high" && r.Changes[1].Severity != "high" {
		t.Fatal("high-risk addition not highlighted")
	}
	for _, change := range r.Changes {
		if !strings.Contains(change.PolicyImpact, change.ToolName) {
			t.Fatalf("review focus is not tool-specific: %#v", change)
		}
	}
}
