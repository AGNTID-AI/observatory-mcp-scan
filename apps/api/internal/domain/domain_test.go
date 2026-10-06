package domain

import "testing"

func TestDeriveConnectionStatusSeparatesAuthenticationFromPartialPipeline(t *testing.T) {
	a := Assessment{
		Mode:   "live",
		Status: StatusPartial,
		Facts: map[string]any{
			"discovery.session_established": false,
			"auth.challenge_present":        true,
			"auth.status_code":              float64(401),
		},
	}
	if got := a.DeriveConnectionStatus(); got != "authentication-required" {
		t.Fatalf("expected authentication-required, got %q", got)
	}

	a.Facts["discovery.session_established"] = true
	if got := a.DeriveConnectionStatus(); got != "connected" {
		t.Fatalf("expected connected despite a later partial stage, got %q", got)
	}
}

func TestNormalizeBackfillsFindingToolNamesFromExistingReplay(t *testing.T) {
	a := Assessment{Mode: "sample", Findings: []Finding{{Replay: &PolicyReplay{ToolNames: []string{"delete_records"}}}}}
	a.Normalize()
	if len(a.Findings[0].ToolNames) != 1 || a.Findings[0].ToolNames[0] != "delete_records" {
		t.Fatalf("finding tool links were not preserved: %#v", a.Findings[0].ToolNames)
	}
}
