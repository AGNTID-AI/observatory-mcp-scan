package ports

import (
	"context"
	"io"

	"github.com/agntid/observatory/api/internal/domain"
)

type AssessmentRepository interface {
	Create(context.Context, *domain.Assessment) error
	Save(context.Context, *domain.Assessment) error
	Get(context.Context, string) (*domain.Assessment, error)
	List(context.Context, int, string) ([]domain.AssessmentSummary, error)
	ClaimNext(context.Context) (*domain.Assessment, error)
	RequestCancel(context.Context, string) error
	CancelRequested(context.Context, string) (bool, error)
}

type EventRepository interface {
	Append(context.Context, string, string, any) (domain.Event, error)
	ListAfter(context.Context, string, uint64) ([]domain.Event, error)
}

type CredentialVault interface {
	Put(context.Context, string, map[string]string) error
	Get(context.Context, string) (map[string]string, error)
	Delete(context.Context, string) error
}

type ArtifactStore interface {
	Put(context.Context, string, string, string, io.Reader) (domain.Artifact, error)
	Open(context.Context, string, string) (io.ReadCloser, domain.Artifact, error)
}

type EngineContext struct {
	Assessment  *domain.Assessment
	Credentials map[string]string
	Baseline    *domain.Assessment
}

type EngineResult struct {
	Facts            map[string]any
	Evidence         []domain.Evidence
	Tools            []domain.ToolProfile
	Server           *domain.ServerProfile
	Context          *domain.ContextProfile
	IdentityExposure *domain.IdentityExposure
	PolicySimulation *domain.PolicySimulation
	RiskChains       []domain.RiskChain
	ContentInventory []domain.ContentItem
	ContentIntegrity *domain.ContentIntegrityProfile
	Readiness        *domain.ReadinessProfile
	CatalogDrift     *domain.CatalogDriftProfile
	OAuth            *domain.OAuthPosture
}

type Engine interface {
	ID() string
	Name() string
	Run(context.Context, EngineContext) (EngineResult, error)
}

type RuleEvaluator interface {
	Rules() []domain.Rule
	Evaluate(context.Context, *domain.Assessment) ([]domain.Finding, error)
}

type Reporter interface {
	Generate(context.Context, *domain.Assessment) ([]domain.Artifact, error)
}
