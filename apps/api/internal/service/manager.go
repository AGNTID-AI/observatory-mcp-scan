package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/agntid/observatory/api/internal/domain"
	"github.com/agntid/observatory/api/internal/ports"
	"github.com/agntid/observatory/api/internal/rules"
	"github.com/agntid/observatory/api/internal/storage"
	"github.com/google/uuid"
)

type CreateInput struct {
	Mode               string
	URL                string
	BearerToken        string
	Headers            map[string]string
	CredentialProfiles []CredentialProfileInput
	Snapshot           *domain.OfflineSnapshot
	OAuth              *domain.OAuthPosture
}

type CredentialProfileInput struct {
	Label       string
	BearerToken string
	Headers     map[string]string
}

type Manager struct {
	repo     ports.AssessmentRepository
	events   ports.EventRepository
	vault    ports.CredentialVault
	rules    ports.RuleEvaluator
	reporter ports.Reporter
	engines  []ports.Engine
	workers  int
	logger   *slog.Logger
	wake     chan struct{}
	cancels  sync.Map
}

func NewManager(repo ports.AssessmentRepository, events ports.EventRepository, vault ports.CredentialVault, evaluator ports.RuleEvaluator, reporter ports.Reporter, engines []ports.Engine, workers int, logger *slog.Logger) *Manager {
	if workers < 1 {
		workers = 2
	}
	return &Manager{repo: repo, events: events, vault: vault, rules: evaluator, reporter: reporter, engines: engines, workers: workers, logger: logger, wake: make(chan struct{}, 1)}
}

func (m *Manager) Create(ctx context.Context, in CreateInput) (*domain.Assessment, error) {
	if in.Mode != "live" && in.Mode != "sample" && in.Mode != "offline" {
		return nil, errors.New("mode must be live, sample, or offline")
	}
	if in.Mode == "offline" && in.Snapshot == nil {
		return nil, errors.New("offline mode requires a metadata snapshot")
	}
	if in.Mode != "offline" && in.Snapshot != nil {
		return nil, errors.New("snapshots are only accepted in offline mode")
	}
	if len(in.CredentialProfiles) > 4 {
		return nil, errors.New("at most four credential profiles are supported")
	}
	u, err := url.Parse(in.URL)
	if err != nil || u.Hostname() == "" {
		return nil, errors.New("a valid target URL is required")
	}
	now := time.Now().UTC()
	a := &domain.Assessment{ID: uuid.NewString(), Mode: in.Mode, Target: domain.Target{Protocol: "mcp", URL: in.URL, Host: u.Hostname()}, Status: domain.StatusQueued, CreatedAt: now, Progress: 0, Facts: map[string]any{}, EngineRuns: initialRuns(m.engines)}
	if in.OAuth != nil {
		a.OAuth = *in.OAuth
	}
	if in.Snapshot != nil {
		a.Tools = append([]domain.ToolProfile(nil), in.Snapshot.Tools...)
		a.Server = in.Snapshot.Server
		a.Server.ToolCount = len(a.Tools)
		a.ContentInventory = append([]domain.ContentItem(nil), in.Snapshot.Prompts...)
		a.ContentInventory = append(a.ContentInventory, in.Snapshot.Resources...)
		if strings.TrimSpace(in.Snapshot.ServerInstructions) != "" {
			a.ContentInventory = append(a.ContentInventory, domain.ContentItem{Kind: "server-instructions", ID: "server-instructions", Name: "Server instructions", Text: in.Snapshot.ServerInstructions, Provenance: "imported"})
			a.Facts["server.instructions"] = in.Snapshot.ServerInstructions
		}
		a.Facts["snapshot.name"] = in.Snapshot.Name
		a.Facts["snapshot.imported"] = true
	}
	a.Normalize()
	if err := m.repo.Create(ctx, a); err != nil {
		return nil, err
	}
	secrets := map[string]string{}
	labels := []string{"Anonymous"}
	for i, profile := range in.CredentialProfiles {
		label := strings.TrimSpace(profile.Label)
		if label == "" {
			label = fmt.Sprintf("Credential %d", i+1)
		}
		labels = append(labels, label)
		prefix := fmt.Sprintf("profile.%d.", i)
		secrets[prefix+"label"] = label
		if profile.BearerToken != "" {
			secrets[prefix+"bearer"] = profile.BearerToken
		}
		for k, v := range profile.Headers {
			secrets[prefix+"header."+k] = v
		}
	}
	if len(in.CredentialProfiles) == 0 {
		if in.BearerToken != "" {
			secrets["profile.0.label"] = "Provided credential"
			secrets["profile.0.bearer"] = in.BearerToken
			labels = append(labels, "Provided credential")
		}
		for k, v := range in.Headers {
			secrets["profile.0.label"] = "Provided credential"
			secrets["profile.0.header."+k] = v
			if len(labels) == 1 {
				labels = append(labels, "Provided credential")
			}
		}
	}
	a.Facts["identity.requested_profiles"] = labels
	if err := m.repo.Save(ctx, a); err != nil {
		return nil, err
	}
	if len(secrets) > 0 {
		if err := m.vault.Put(ctx, a.ID, secrets); err != nil {
			return nil, err
		}
	}
	_, _ = m.events.Append(ctx, a.ID, "assessment", map[string]any{"status": "queued", "progress": 0})
	select {
	case m.wake <- struct{}{}:
	default:
	}
	return a, nil
}

func initialRuns(engines []ports.Engine) []domain.EngineRun {
	runs := []domain.EngineRun{{ID: "queue", Name: "Queue Assessment", Status: "completed", Progress: 100, Message: "Assessment queued"}}
	for _, e := range engines {
		runs = append(runs, domain.EngineRun{ID: e.ID(), Name: e.Name(), Status: "pending"})
	}
	runs = append(runs, domain.EngineRun{ID: "rule-evaluation", Name: "Rule Evaluation", Status: "pending"}, domain.EngineRun{ID: "report-generation", Name: "Report Generation", Status: "pending"})
	return runs
}

func (m *Manager) Start(ctx context.Context) {
	jobs := make(chan *domain.Assessment, m.workers)
	for i := 0; i < m.workers; i++ {
		go func() {
			for a := range jobs {
				m.run(ctx, a)
			}
		}()
	}
	go func() {
		ticker := time.NewTicker(750 * time.Millisecond)
		defer ticker.Stop()
		defer close(jobs)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-m.wake:
			}
			for {
				a, err := m.repo.ClaimNext(ctx)
				if errors.Is(err, storage.ErrNotFound) {
					break
				}
				if err != nil {
					m.logger.Error("claim assessment", "error", err)
					break
				}
				select {
				case jobs <- a:
				case <-ctx.Done():
					return
				}
				if len(jobs) >= m.workers {
					break
				}
			}
		}
	}()
}

func (m *Manager) run(parent context.Context, a *domain.Assessment) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	m.cancels.Store(a.ID, cancel)
	defer func() { cancel(); m.cancels.Delete(a.ID); _ = m.vault.Delete(context.Background(), a.ID) }()
	creds, err := m.vault.Get(ctx, a.ID)
	if err != nil {
		m.fail(ctx, a, err)
		return
	}
	partial := false
	baseline := m.findBaseline(ctx, a)
	for i, engine := range m.engines {
		if ctx.Err() != nil {
			m.cancel(context.Background(), a)
			return
		}
		if requested, _ := m.repo.CancelRequested(ctx, a.ID); requested {
			m.cancel(ctx, a)
			return
		}
		run := findRun(a, engine.ID())
		started := time.Now().UTC()
		run.Status = "running"
		run.StartedAt = &started
		run.Progress = 10
		a.CurrentStage = engine.ID()
		a.Progress = stageProgress(i, len(m.engines), 10)
		_ = m.repo.Save(ctx, a)
		_, _ = m.events.Append(ctx, a.ID, "stage", run)
		stageCtx, stageCancel := context.WithTimeout(ctx, 30*time.Second)
		if a.Mode == "sample" {
			select {
			case <-time.After(180 * time.Millisecond):
			case <-stageCtx.Done():
			}
		}
		result, runErr := engine.Run(stageCtx, ports.EngineContext{Assessment: a, Credentials: creds, Baseline: baseline})
		stageCancel()
		finished := time.Now().UTC()
		run.CompletedAt = &finished
		run.DurationMs = finished.Sub(started).Milliseconds()
		run.Progress = 100
		if runErr != nil {
			// Engines may return useful diagnostics alongside a partial failure.
			// Preserve them so the UI can distinguish authentication rejection
			// from an endpoint that never responded.
			merge(a, result)
			run.Status = "partial"
			run.Message = runErr.Error()
			partial = true
			a.Facts["engine."+engine.ID()+".failed"] = true
			if engine.ID() == "discovery" {
				a.Facts["discovery.session_established"] = false
				a.Facts["discovery.error"] = runErr.Error()
			}
			_, _ = m.events.Append(ctx, a.ID, "error", map[string]any{"stage": engine.ID(), "detail": runErr.Error()})
		} else {
			run.Status = "completed"
			run.Message = fmt.Sprintf("%s completed", engine.Name())
			merge(a, result)
			if a.Facts["engine."+engine.ID()+".assessed"] == false {
				run.Status = "not-assessed"
				run.Message = engine.Name() + " requires a live target; not assessed from imported metadata"
			} else if engine.ID() == "authorization" && a.Facts["authorization.assessed"] != true {
				run.Status = "not-assessed"
				run.Message = "Tool execution authorization was not assessed; catalog visibility only"
			}
		}
		a.Progress = stageProgress(i, len(m.engines), 100)
		_ = m.repo.Save(ctx, a)
		_, _ = m.events.Append(ctx, a.ID, "stage", run)
	}
	if m.runRules(ctx, a) {
		partial = true
	}
	reportFailed := m.runReports(ctx, a)
	if reportFailed {
		partial = true
	}
	now := time.Now().UTC()
	a.CompletedAt = &now
	a.CurrentStage = ""
	a.Progress = 100
	if partial {
		a.Status = domain.StatusPartial
	} else {
		a.Status = domain.StatusCompleted
	}
	a.ConnectionStatus = a.DeriveConnectionStatus()
	if !reportFailed {
		if err := m.reporter.Finalize(ctx, a); err != nil {
			a.Status = domain.StatusPartial
			run := findRun(a, "report-generation")
			run.Status = "partial"
			run.Message = "Canonical report could not be finalized"
			m.logger.Error("finalize canonical report", "assessment_id", a.ID, "error", err)
			_, _ = m.events.Append(ctx, a.ID, "error", map[string]any{"stage": run.ID, "detail": run.Message})
		} else {
			_, _ = m.events.Append(ctx, a.ID, "artifact", a.Artifacts[0])
		}
	}
	_ = m.repo.Save(ctx, a)
	_, _ = m.events.Append(ctx, a.ID, "completed", map[string]any{"status": a.Status, "score": a.Scorecard.Overall, "coverage": a.Scorecard.Coverage})
}

func (m *Manager) runRules(ctx context.Context, a *domain.Assessment) bool {
	run := findRun(a, "rule-evaluation")
	start := time.Now().UTC()
	run.Status = "running"
	run.StartedAt = &start
	a.CurrentStage = run.ID
	a.Progress = 90
	_ = m.repo.Save(ctx, a)
	_, _ = m.events.Append(ctx, a.ID, "stage", run)
	findings, err := m.rules.Evaluate(ctx, a)
	if err != nil {
		run.Status = "partial"
		run.Message = err.Error()
	} else {
		a.Findings = findings
		a.Recommendations = nil
		for _, f := range findings {
			a.Recommendations = append(a.Recommendations, f.Recommendation)
			_, _ = m.events.Append(ctx, a.ID, "finding", f)
		}
		rules.Score(a)
		summarize(a)
		run.Status = "completed"
		run.Message = fmt.Sprintf("Evaluated %d rules and produced %d findings", len(m.rules.Rules()), len(findings))
	}
	end := time.Now().UTC()
	run.CompletedAt = &end
	run.DurationMs = end.Sub(start).Milliseconds()
	run.Progress = 100
	_ = m.repo.Save(ctx, a)
	_, _ = m.events.Append(ctx, a.ID, "stage", run)
	return err != nil
}
func (m *Manager) runReports(ctx context.Context, a *domain.Assessment) bool {
	run := findRun(a, "report-generation")
	start := time.Now().UTC()
	run.Status = "running"
	run.StartedAt = &start
	a.CurrentStage = run.ID
	a.Progress = 95
	_ = m.repo.Save(ctx, a)
	_, _ = m.events.Append(ctx, a.ID, "stage", run)
	artifacts, err := m.reporter.Generate(ctx, a)
	if err != nil {
		run.Status = "partial"
		run.Message = err.Error()
	} else {
		a.Artifacts = artifacts
		run.Status = "completed"
		run.Message = fmt.Sprintf("Generated %d report artifacts", len(artifacts)+1)
		for _, artifact := range artifacts {
			_, _ = m.events.Append(ctx, a.ID, "artifact", artifact)
		}
	}
	end := time.Now().UTC()
	run.CompletedAt = &end
	run.DurationMs = end.Sub(start).Milliseconds()
	run.Progress = 100
	_ = m.repo.Save(ctx, a)
	_, _ = m.events.Append(ctx, a.ID, "stage", run)
	return err != nil
}

func merge(a *domain.Assessment, r ports.EngineResult) {
	if a.Facts == nil {
		a.Facts = map[string]any{}
	}
	for k, v := range r.Facts {
		a.Facts[k] = v
	}
	a.Evidence = append(a.Evidence, r.Evidence...)
	if r.Tools != nil {
		a.Tools = r.Tools
		if a.Server.ToolCount == 0 || len(r.Tools) > a.Server.ToolCount {
			a.Server.ToolCount = len(r.Tools)
		}
	}
	if r.Server != nil {
		a.Server = *r.Server
	}
	if r.Context != nil {
		a.Context = *r.Context
	}
	if r.IdentityExposure != nil {
		a.IdentityExposure = *r.IdentityExposure
	}
	if r.PolicySimulation != nil {
		a.PolicySimulation = *r.PolicySimulation
	}
	if r.RiskChains != nil {
		a.RiskChains = r.RiskChains
	}
	if r.ContentInventory != nil {
		a.ContentInventory = r.ContentInventory
	}
	if r.ContentIntegrity != nil {
		a.ContentIntegrity = *r.ContentIntegrity
	}
	if r.Readiness != nil {
		a.Readiness = *r.Readiness
	}
	if r.CatalogDrift != nil {
		a.CatalogDrift = *r.CatalogDrift
	}
	if r.OAuth != nil {
		completed := a.OAuth.AuthorizationCompleted
		method := a.OAuth.RegistrationMethod
		identities := append([]string(nil), a.OAuth.AuthorizedIdentities...)
		a.OAuth = *r.OAuth
		if completed {
			a.OAuth.AuthorizationCompleted = true
			a.OAuth.RegistrationMethod = method
			a.OAuth.AuthorizedIdentities = identities
		}
	}
}

func (m *Manager) findBaseline(ctx context.Context, current *domain.Assessment) *domain.Assessment {
	items, err := m.repo.List(ctx, 100, "")
	if err != nil {
		return nil
	}
	for _, item := range items {
		if item.ID == current.ID || item.Target.URL != current.Target.URL {
			continue
		}
		if item.Status != domain.StatusCompleted && item.Status != domain.StatusPartial {
			continue
		}
		baseline, getErr := m.repo.Get(ctx, item.ID)
		if getErr == nil && len(baseline.Tools) > 0 {
			return baseline
		}
	}
	return nil
}
func findRun(a *domain.Assessment, id string) *domain.EngineRun {
	for i := range a.EngineRuns {
		if a.EngineRuns[i].ID == id {
			return &a.EngineRuns[i]
		}
	}
	a.EngineRuns = append(a.EngineRuns, domain.EngineRun{ID: id, Name: id})
	return &a.EngineRuns[len(a.EngineRuns)-1]
}
func stageProgress(i, total, within int) int {
	return 2 + int(float64(i*100+within)/float64(total*100)*86)
}
func summarize(a *domain.Assessment) {
	if a.DeriveConnectionStatus() == "authentication-required" {
		a.ExecutiveSummary = "The MCP endpoint responded, but no supplied identity established a session. Authentication posture and public diagnostics were collected; tool, protocol, and AI-readiness results were not assessed."
		a.TechnicalSummary = "The live endpoint required authentication and no configured identity completed MCP initialization. No tool catalog was discovered and no MCP tools were invoked."
		return
	}
	if a.DeriveConnectionStatus() == "connection-failed" {
		a.ExecutiveSummary = "Observatory could not establish an MCP session, so tool, protocol, and AI-readiness results were not assessed. Connection diagnostics and a failure report are available."
		a.TechnicalSummary = "No configured identity completed MCP initialization. No tool catalog was discovered and no MCP tools were invoked."
		return
	}
	risk := "no critical or high-severity findings matched the available evidence"
	if a.Risk.Critical > 0 || a.Risk.High > 0 {
		risk = "critical or high-severity findings require attention"
	} else if a.Risk.Medium > 0 {
		risk = "several moderate improvements are recommended"
	}
	a.ExecutiveSummary = fmt.Sprintf("%s achieved an overall readiness score of %d/100 with %.0f%% assessment coverage; %s.", fallback(a.Server.Name, a.Target.Host), a.Scorecard.Overall, a.Scorecard.Coverage, risk)
	source := "live metadata"
	if a.Mode == "offline" {
		source = "imported metadata"
	} else if a.Mode == "sample" {
		source = "clearly labelled sample metadata"
	}
	a.TechnicalSummary = fmt.Sprintf("The %s assessment reviewed MCP %s and %d tools, producing %d rule-backed findings. No MCP tools were invoked.", source, fallback(a.Server.ProtocolVersion, "unknown"), len(a.Tools), len(a.Findings))
}
func fallback(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}
func (m *Manager) fail(ctx context.Context, a *domain.Assessment, err error) {
	now := time.Now().UTC()
	a.Status = domain.StatusFailed
	a.Error = err.Error()
	a.CompletedAt = &now
	_ = m.repo.Save(ctx, a)
	_, _ = m.events.Append(ctx, a.ID, "error", map[string]any{"detail": err.Error()})
}
func (m *Manager) cancel(ctx context.Context, a *domain.Assessment) {
	now := time.Now().UTC()
	a.Status = domain.StatusCanceled
	a.CompletedAt = &now
	a.CurrentStage = ""
	_ = m.repo.Save(ctx, a)
	_, _ = m.events.Append(ctx, a.ID, "completed", map[string]any{"status": "canceled"})
}
func (m *Manager) Cancel(ctx context.Context, id string) error {
	if err := m.repo.RequestCancel(ctx, id); err != nil {
		return err
	}
	if v, ok := m.cancels.Load(id); ok {
		v.(context.CancelFunc)()
	}
	return nil
}
func (m *Manager) Get(ctx context.Context, id string) (*domain.Assessment, error) {
	a, err := m.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if needsReachabilityRepair(a) {
		a.Facts["discovery.session_established"] = false
		a.Facts["discovery.reachable"] = false
		for _, run := range a.EngineRuns {
			if run.ID == "discovery" {
				a.Facts["discovery.error"] = run.Message
				break
			}
		}
		if findings, evalErr := m.rules.Evaluate(ctx, a); evalErr == nil {
			a.Findings = findings
			a.Recommendations = []domain.Recommendation{}
			for _, finding := range findings {
				a.Recommendations = append(a.Recommendations, finding.Recommendation)
			}
			rules.Score(a)
			summarize(a)
			if artifacts, reportErr := m.reporter.Generate(ctx, a); reportErr == nil {
				a.Artifacts = artifacts
			}
			_ = m.repo.Save(ctx, a)
		}
	}
	return a, nil
}

func needsReachabilityRepair(a *domain.Assessment) bool {
	if a.Status != domain.StatusPartial {
		return false
	}
	if _, observed := a.Facts["discovery.reachable"]; observed {
		return false
	}
	for _, run := range a.EngineRuns {
		if run.ID == "discovery" && run.Status == "partial" {
			return true
		}
	}
	return false
}
func (m *Manager) List(ctx context.Context, limit int, cursor string) ([]domain.AssessmentSummary, error) {
	return m.repo.List(ctx, limit, cursor)
}
func (m *Manager) Rules() []domain.Rule { return m.rules.Rules() }
func (m *Manager) Dashboard(ctx context.Context) (map[string]any, error) {
	items, err := m.repo.List(ctx, 100, "")
	if err != nil {
		return nil, err
	}
	severity := domain.RiskProfile{}
	modes := map[string]int{"live": 0, "sample": 0, "offline": 0}
	sum := 0
	completed := 0
	for _, a := range items {
		modes[a.Mode]++
		severity.Critical += a.Risk.Critical
		severity.High += a.Risk.High
		severity.Medium += a.Risk.Medium
		severity.Low += a.Risk.Low
		severity.Info += a.Risk.Info
		if (a.Status == domain.StatusCompleted || a.Status == domain.StatusPartial) && a.ConnectionStatus != "authentication-required" && a.ConnectionStatus != "connection-failed" {
			sum += a.OverallScore
			completed++
		}
	}
	avg := 0
	if completed > 0 {
		avg = sum / completed
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	recent := items
	if len(recent) > 6 {
		recent = recent[:6]
	}
	return map[string]any{"totalAssessments": len(items), "averageScore": avg, "completed": completed, "risk": severity, "modes": modes, "recent": recent}, nil
}
