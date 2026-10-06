package readiness

import "testing"

func TestAnalyzePenalizesOpenUnstructuredContract(t *testing.T) {
	r := Analyze(Tool{Name: "delete", Description: "Delete all records for a tenant.", Mutating: true, InputSchema: map[string]any{"type": "object", "properties": map[string]any{"id": map[string]any{"type": "string"}}}})
	if r.Score >= 70 {
		t.Fatalf("expected weak score, got %d", r.Score)
	}
	if r.Coverage >= 100 {
		t.Fatalf("unknown idempotency should reduce coverage: %.0f", r.Coverage)
	}
}
func TestAnalyzeStrongContract(t *testing.T) {
	yes := true
	r := Analyze(Tool{Name: "set", Description: "Set an approved account status for one customer.", Mutating: true, IdempotentHint: &yes, InputSchema: map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{"status": map[string]any{"type": "string", "enum": []any{"on", "off"}}}, "required": []any{"status"}}, OutputSchema: map[string]any{"type": "object"}})
	if r.Score != 100 {
		t.Fatalf("got %d", r.Score)
	}
}
