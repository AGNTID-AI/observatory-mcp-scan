package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agntid/observatory/api/internal/domain"
	"github.com/agntid/observatory/api/internal/ports"
	"github.com/agntid/observatory/api/internal/reporting"
	"github.com/agntid/observatory/api/internal/scanner"
	"github.com/agntid/observatory/api/internal/storage"
)

type emptyRules struct{}

func (emptyRules) Rules() []domain.Rule { return nil }
func (emptyRules) Evaluate(context.Context, *domain.Assessment) ([]domain.Finding, error) {
	return nil, nil
}

type failCanonicalStore struct{ ports.ArtifactStore }

func (f failCanonicalStore) Put(ctx context.Context, assessmentID, name, contentType string, r io.Reader) (domain.Artifact, error) {
	if name == "assessment.json" {
		return domain.Artifact{}, errors.New("fixture canonical failure")
	}
	return f.ArtifactStore.Put(ctx, assessmentID, name, contentType, r)
}

func TestOfflineTerminalReportsAndUnavailableStages(t *testing.T) {
	for _, stageFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "completed", true: "partial"}[stageFailure], func(t *testing.T) {
			store, artifacts, manager := reportTestManager(t, false)
			if stageFailure {
				manager.engines = append(manager.engines, failingEngine{})
			}
			a, err := manager.Create(context.Background(), CreateInput{Mode: "offline", URL: "https://example.com/mcp", Snapshot: &domain.OfflineSnapshot{Name: "Fixture catalog"}})
			if err != nil {
				t.Fatal(err)
			}
			claimed, err := store.ClaimNext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			manager.run(context.Background(), claimed)
			got, err := store.Get(context.Background(), a.ID)
			if err != nil {
				t.Fatal(err)
			}
			expected := domain.StatusCompleted
			if stageFailure {
				expected = domain.StatusPartial
			}
			if got.Status != expected || got.Progress != 100 || got.CompletedAt == nil {
				t.Fatalf("invalid terminal state: %#v", got)
			}
			if !strings.Contains(got.ExecutiveSummary, "available evidence") || strings.Contains(got.ExecutiveSummary, "risk is low") {
				t.Fatalf("summary overstates security assurance: %s", got.ExecutiveSummary)
			}
			for _, id := range []string{"transport", "authentication", "oauth-posture", "authorization", "operational"} {
				run := findRun(got, id)
				if run.Status != "not-assessed" {
					t.Fatalf("%s status = %s", id, run.Status)
				}
			}
			if len(got.Artifacts) != 6 {
				t.Fatalf("got %d artifacts", len(got.Artifacts))
			}
			reader, _, err := artifacts.Open(context.Background(), got.ID, "assessment.json")
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				t.Fatal(err)
			}
			var exported domain.Assessment
			if err := json.Unmarshal(body, &exported); err != nil {
				t.Fatal(err)
			}
			if exported.Status != got.Status || exported.Progress != got.Progress || exported.CurrentStage != "" || !exported.CompletedAt.Equal(*got.CompletedAt) {
				t.Fatalf("export differs from terminal state: %#v", exported)
			}
			if findRun(&exported, "report-generation").Status != "completed" {
				t.Fatal("export contains unfinished report stage")
			}
			sum := sha256.Sum256(body)
			if got.Artifacts[0].SHA256 != hex.EncodeToString(sum[:]) {
				t.Fatal("canonical artifact hash was not refreshed")
			}
			if len(exported.Artifacts) != 5 {
				t.Fatal("export must include other artifacts and exclude its own hash")
			}
			for _, artifact := range exported.Artifacts {
				if artifact.ID == "assessment.json" {
					t.Fatal("self-referential manifest entry")
				}
			}
		})
	}
}

func TestCanonicalFinalizationFailureIsPartial(t *testing.T) {
	store, artifacts, manager := reportTestManager(t, true)
	_, err := manager.Create(context.Background(), CreateInput{Mode: "offline", URL: "https://example.com/mcp", Snapshot: &domain.OfflineSnapshot{Name: "Fixture catalog"}})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimNext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	manager.run(context.Background(), claimed)
	got, err := store.Get(context.Background(), claimed.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != domain.StatusPartial || findRun(got, "report-generation").Status != "partial" {
		t.Fatal("report finalization failure claimed completion")
	}
	if len(got.Artifacts) != 5 {
		t.Fatalf("got %d artifacts", len(got.Artifacts))
	}
	if _, _, err := artifacts.Open(context.Background(), got.ID, "assessment.json"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("unfinished canonical snapshot was published")
	}
}

type failingEngine struct{}

func (failingEngine) ID() string   { return "fixture-failure" }
func (failingEngine) Name() string { return "Fixture failure" }
func (failingEngine) Run(context.Context, ports.EngineContext) (ports.EngineResult, error) {
	return ports.EngineResult{}, errors.New("fixture stage failure")
}

func reportTestManager(t *testing.T, fail bool) (*storage.Store, storage.FileArtifacts, *Manager) {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "test.db"), filepath.Join(dir, "key"), "")
	if err != nil {
		t.Fatal(err)
	}
	artifacts := storage.FileArtifacts{Root: filepath.Join(dir, "artifacts")}
	var artifactStore ports.ArtifactStore = artifacts
	if fail {
		artifactStore = failCanonicalStore{artifacts}
	}
	engines := []ports.Engine{}
	for _, id := range []string{"transport", "authentication", "oauth-posture", "authorization", "operational"} {
		engines = append(engines, scanner.StageEngine{StageID: id, StageName: id})
	}
	manager := NewManager(store, store, storage.Vault{Store: store}, emptyRules{}, reporting.Generator{Store: artifactStore}, engines, 1, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return store, artifacts, manager
}
