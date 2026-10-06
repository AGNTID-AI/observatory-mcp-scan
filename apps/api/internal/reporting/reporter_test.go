package reporting_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/agntid/observatory/api/internal/domain"
	"github.com/agntid/observatory/api/internal/reporting"
	"github.com/agntid/observatory/api/internal/storage"
)

func TestGenerateIncludesValidSARIF(t *testing.T) {
	store := storage.FileArtifacts{Root: t.TempDir()}
	a := &domain.Assessment{ID: "assessment-1", Mode: "offline", Target: domain.Target{URL: "https://example.com/mcp"}, CreatedAt: time.Now(), Findings: []domain.Finding{{RuleID: "OBS-TEST", Title: "Test finding", Severity: "high", Description: "A test finding", Classification: "policy-opportunity", Replay: &domain.PolicyReplay{Title: "A safe example", Observed: "Observed delete_records.", Trigger: "A cleanup request.", UnprotectedPath: "The capability is attempted.", AgntIDDecision: "Require approval.", ProtectedOutcome: "The operation waits.", ToolNames: []string{"delete_records"}, Disclaimer: "No tool was invoked."}}}, ContentIntegrity: domain.ContentIntegrityProfile{Signals: []domain.ContentSignal{{RuleID: "CONTENT-TEST", Title: "Content signal", Severity: "medium", Summary: "Review metadata", SurfaceKind: "tool", SurfaceID: "demo"}}}}
	a.Tools = []domain.ToolProfile{{Name: "fetch_page", Schema: domain.SchemaAnalysis{InputRisks: []domain.InputRisk{{Kind: "URL", Path: "$.target_url", Severity: "medium", Reason: "network destination", Constrained: false}}}, Classification: domain.ToolClassification{IsDiscover: true, ExecutionSurface: "REMOTE_API", Effects: []string{"READ"}}}}
	a.Normalize()
	artifacts, err := (reporting.Generator{Store: store}).Generate(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 6 {
		t.Fatalf("expected 6 artifacts, got %d", len(artifacts))
	}
	reader, _, err := store.Open(context.Background(), a.ID, "assessment.sarif")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	body, _ := io.ReadAll(reader)
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if document["version"] != "2.1.0" {
		t.Fatalf("unexpected SARIF version: %v", document["version"])
	}
	htmlReader, _, err := store.Open(context.Background(), a.ID, "technical-report.html")
	if err != nil {
		t.Fatal(err)
	}
	defer htmlReader.Close()
	htmlBody, _ := io.ReadAll(htmlReader)
	for _, expected := range [][]byte{[]byte("Why it matters"), []byte("This is an indicator check, not a safety score"), []byte("Lower coverage means uncertainty, not failure"), []byte("Baseline created"), []byte("View illustrative policy replay"), []byte("Observed delete_records"), []byte("No tool was invoked"), []byte("OWASP-aligned input and output trust boundaries"), []byte("URL $.target_url (unconstrained)"), []byte("No output schema; remote or open-world result inferred")} {
		if !bytes.Contains(htmlBody, expected) {
			t.Fatalf("technical report missing %q", expected)
		}
	}
	if bytes.Contains(htmlBody, []byte("No deterministic content-integrity signature matched")) {
		t.Fatal("technical report exposes analyzer jargon in empty state")
	}
}

func TestOAuthReportDistinguishesUnavailableFromObserved(t *testing.T) {
	for _, tc := range []struct{ name, mode, status, want string }{
		{"offline", "offline", "", "OAuth protection was not assessed."},
		{"unavailable", "live", "unavailable", "OAuth protection was not assessed."},
		{"unassessed", "live", "not-assessed", "OAuth protection was not assessed."},
		{"observed", "live", "not-protected", "The anonymous initialization probe did not observe an OAuth requirement."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.FileArtifacts{Root: t.TempDir()}
			a := &domain.Assessment{ID: "fixture", Mode: tc.mode, OAuth: domain.OAuthPosture{Status: tc.status}}
			a.Normalize()
			if _, err := (reporting.Generator{Store: store}).Generate(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			reader, _, err := store.Open(context.Background(), a.ID, "technical-report.md")
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			body, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(body, []byte(tc.want)) {
				t.Fatalf("missing accurate OAuth explanation: %s", body)
			}
			if bytes.Contains(body, []byte("OAuth protection was not required")) {
				t.Fatal("report overstates missing OAuth evidence")
			}
		})
	}
}
