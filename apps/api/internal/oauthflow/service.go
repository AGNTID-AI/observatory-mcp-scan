package oauthflow

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/agntid/observatory/api/internal/domain"
	"github.com/agntid/observatory/api/internal/ports"
	"github.com/agntid/observatory/api/internal/scanner"
	"github.com/google/uuid"
	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

const sessionLifetime = 10 * time.Minute

var ErrNotFound = errors.New("oauth session not found")

type SessionView struct {
	ID               string              `json:"id"`
	Label            string              `json:"label"`
	TargetURL        string              `json:"targetUrl"`
	Status           string              `json:"status"`
	AuthorizationURL string              `json:"authorizationUrl,omitempty"`
	Profile          domain.OAuthPosture `json:"profile"`
	Error            string              `json:"error,omitempty"`
	CreatedAt        time.Time           `json:"createdAt"`
	ExpiresAt        time.Time           `json:"expiresAt"`
}

type callbackResult struct {
	result *mcpauth.AuthorizationResult
	err    error
}

type oauthSession struct {
	view          SessionView
	expectedState string
	callback      chan callbackResult
	ready         chan struct{}
	done          chan struct{}
	readyOnce     sync.Once
	doneOnce      sync.Once
	cancel        context.CancelFunc
}

type Service struct {
	policy      scanner.NetworkPolicy
	vault       ports.CredentialVault
	callbackURL string
	logger      *slog.Logger
	mu          sync.RWMutex
	sessions    map[string]*oauthSession
	byState     map[string]string
}

func New(policy scanner.NetworkPolicy, vault ports.CredentialVault, callbackURL string, logger *slog.Logger) (*Service, error) {
	u, err := url.Parse(callbackURL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname()))) {
		return nil, errors.New("OAuth callback URL must use HTTPS or HTTP on localhost")
	}
	return &Service{policy: policy, vault: vault, callbackURL: callbackURL, logger: logger, sessions: map[string]*oauthSession{}, byState: map[string]string{}}, nil
}

func (s *Service) Start(ctx context.Context, targetURL, label string) (SessionView, error) {
	label = strings.TrimSpace(label)
	if label == "" {
		label = "OAuth identity"
	}
	if _, _, err := s.policy.ValidateURL(ctx, targetURL); err != nil {
		return SessionView{}, err
	}
	inspectionCtx, cancelInspection := context.WithTimeout(ctx, 20*time.Second)
	inspection, err := scanner.InspectOAuth(inspectionCtx, targetURL, s.policy)
	cancelInspection()
	if err != nil {
		return SessionView{}, fmt.Errorf("OAuth discovery failed: %w", err)
	}
	now := time.Now().UTC()
	view := SessionView{ID: uuid.NewString(), Label: label, TargetURL: targetURL, Status: "discovering", Profile: inspection.Profile, CreatedAt: now, ExpiresAt: now.Add(sessionLifetime)}
	flowCtx, cancel := context.WithTimeout(context.Background(), sessionLifetime)
	session := &oauthSession{view: view, callback: make(chan callbackResult, 1), ready: make(chan struct{}), done: make(chan struct{}), cancel: cancel}
	s.mu.Lock()
	s.sessions[view.ID] = session
	s.mu.Unlock()

	if !inspection.Profile.Protected {
		s.update(view.ID, func(current *oauthSession) { current.view.Status = "not-required" })
		signalReady(session)
		signalDone(session)
		cancel()
		return s.Get(view.ID)
	}
	if !inspection.Profile.DCRSupported {
		s.update(view.ID, func(current *oauthSession) {
			current.view.Status = "unsupported"
			current.view.Error = "The authorization server does not advertise a Dynamic Client Registration endpoint. Use a pre-issued bearer token for this assessment."
		})
		signalReady(session)
		signalDone(session)
		cancel()
		return s.Get(view.ID)
	}

	go s.run(flowCtx, session)
	select {
	case <-session.ready:
		return s.Get(view.ID)
	case <-session.done:
		return s.Get(view.ID)
	case <-ctx.Done():
		return SessionView{}, ctx.Err()
	case <-time.After(20 * time.Second):
		return s.Get(view.ID)
	}
}

func (s *Service) run(ctx context.Context, session *oauthSession) {
	defer signalDone(session)
	httpClient := s.policy.MultiHostClient()
	handler, err := mcpauth.NewAuthorizationCodeHandler(&mcpauth.AuthorizationCodeHandlerConfig{
		RedirectURL: s.callbackURL,
		DynamicClientRegistrationConfig: &mcpauth.DynamicClientRegistrationConfig{Metadata: &oauthex.ClientRegistrationMetadata{
			RedirectURIs: []string{s.callbackURL}, TokenEndpointAuthMethod: "none",
			GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"},
			ClientName: "AgntID Observatory", SoftwareID: "agntid-observatory", SoftwareVersion: "0.3.0",
		}},
		Client: httpClient,
		AuthorizationCodeFetcher: func(fetchCtx context.Context, args *mcpauth.AuthorizationArgs) (*mcpauth.AuthorizationResult, error) {
			authURL, parseErr := url.Parse(args.URL)
			if parseErr != nil {
				return nil, parseErr
			}
			state := authURL.Query().Get("state")
			if state == "" {
				return nil, errors.New("authorization URL did not include state")
			}
			s.mu.Lock()
			session.expectedState = state
			session.view.AuthorizationURL = args.URL
			session.view.Status = "awaiting-authorization"
			s.byState[state] = session.view.ID
			s.mu.Unlock()
			signalReady(session)
			select {
			case callback := <-session.callback:
				return callback.result, callback.err
			case <-fetchCtx.Done():
				return nil, fetchCtx.Err()
			}
		},
	})
	if err != nil {
		s.fail(session, err)
		return
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "agntid-observatory", Version: "0.3.0"}, nil)
	transport := &mcp.StreamableClientTransport{Endpoint: session.view.TargetURL, HTTPClient: httpClient, OAuthHandler: handler, DisableStandaloneSSE: true, MaxRetries: -1}
	mcpSession, err := client.Connect(ctx, transport, nil)
	if err != nil {
		s.fail(session, err)
		return
	}
	mcpSession.Close()
	tokenSource, err := handler.TokenSource(ctx)
	if err != nil || tokenSource == nil {
		if err == nil {
			err = errors.New("authorization completed without a token source")
		}
		s.fail(session, err)
		return
	}
	token, err := tokenSource.Token()
	if err != nil || token.AccessToken == "" {
		if err == nil {
			err = errors.New("authorization completed without an access token")
		}
		s.fail(session, err)
		return
	}
	values := map[string]string{"access_token": token.AccessToken, "token_type": token.TokenType}
	if !token.Expiry.IsZero() {
		values["expires_at"] = token.Expiry.UTC().Format(time.RFC3339)
	}
	if err := s.vault.Put(context.Background(), vaultID(session.view.ID), values); err != nil {
		s.fail(session, err)
		return
	}
	s.mu.Lock()
	delete(s.byState, session.expectedState)
	session.view.Status = "authorized"
	session.view.AuthorizationURL = ""
	session.view.Profile.AuthorizationCompleted = true
	session.view.Profile.RegistrationMethod = "dynamic"
	session.view.Profile.AuthorizedIdentities = []string{session.view.Label}
	s.mu.Unlock()
}

func (s *Service) Complete(state, code, oauthError, errorDescription, issuer string) error {
	state = strings.TrimSpace(state)
	if state == "" {
		return errors.New("OAuth callback is missing state")
	}
	s.mu.RLock()
	id := s.byState[state]
	session := s.sessions[id]
	s.mu.RUnlock()
	if session == nil || session.expectedState != state {
		return ErrNotFound
	}
	if issuer != "" && session.view.Profile.Issuer != "" && issuer != session.view.Profile.Issuer {
		return errors.New("authorization response issuer does not match discovered issuer")
	}
	result := callbackResult{}
	if oauthError != "" {
		result.err = fmt.Errorf("authorization server returned %s: %s", oauthError, strings.TrimSpace(errorDescription))
	} else if strings.TrimSpace(code) == "" {
		result.err = errors.New("OAuth callback is missing the authorization code")
	} else {
		result.result = &mcpauth.AuthorizationResult{Code: code, State: state}
	}
	s.mu.Lock()
	if result.err != nil {
		session.view.Status = "denied"
		session.view.Error = redactOAuthError(result.err)
	} else {
		session.view.Status = "exchanging-token"
	}
	s.mu.Unlock()
	select {
	case session.callback <- result:
		return nil
	default:
		return errors.New("OAuth callback was already processed")
	}
}

func (s *Service) Get(id string) (SessionView, error) {
	s.mu.RLock()
	session := s.sessions[id]
	if session == nil {
		s.mu.RUnlock()
		return SessionView{}, ErrNotFound
	}
	view := session.view
	s.mu.RUnlock()
	if time.Now().After(view.ExpiresAt) && !terminal(view.Status) {
		s.update(id, func(current *oauthSession) {
			current.view.Status = "expired"
			current.view.AuthorizationURL = ""
			current.view.Error = "The OAuth authorization session expired. Start a new connection."
			current.cancel()
		})
		_ = s.vault.Delete(context.Background(), vaultID(id))
		s.mu.RLock()
		view = s.sessions[id].view
		s.mu.RUnlock()
	}
	return view, nil
}

// Consume returns a short-lived access token exactly once and removes its
// encrypted OAuth-session envelope. The assessment manager immediately places
// it into the assessment-specific credential envelope.
func (s *Service) Consume(ctx context.Context, id, targetURL, label string) (string, domain.OAuthPosture, error) {
	view, err := s.Get(id)
	if err != nil {
		return "", domain.OAuthPosture{}, err
	}
	if view.Status != "authorized" {
		return "", domain.OAuthPosture{}, fmt.Errorf("OAuth session is %s", view.Status)
	}
	if view.TargetURL != targetURL {
		return "", domain.OAuthPosture{}, errors.New("OAuth session target does not match assessment target")
	}
	if strings.TrimSpace(label) != "" && view.Label != strings.TrimSpace(label) {
		return "", domain.OAuthPosture{}, errors.New("OAuth session identity label does not match")
	}
	values, err := s.vault.Get(ctx, vaultID(id))
	if err != nil || values["access_token"] == "" {
		return "", domain.OAuthPosture{}, errors.New("OAuth access token is unavailable")
	}
	if err := s.vault.Delete(ctx, vaultID(id)); err != nil {
		return "", domain.OAuthPosture{}, err
	}
	s.update(id, func(current *oauthSession) { current.view.Status = "consumed" })
	return values["access_token"], view.Profile, nil
}

func (s *Service) Cancel(id string) error {
	s.mu.Lock()
	session := s.sessions[id]
	if session == nil {
		s.mu.Unlock()
		return ErrNotFound
	}
	delete(s.byState, session.expectedState)
	session.view.Status = "canceled"
	session.view.AuthorizationURL = ""
	session.cancel()
	s.mu.Unlock()
	_ = s.vault.Delete(context.Background(), vaultID(id))
	return nil
}

func (s *Service) fail(session *oauthSession, err error) {
	s.mu.Lock()
	delete(s.byState, session.expectedState)
	session.view.Status = "failed"
	session.view.AuthorizationURL = ""
	session.view.Error = redactOAuthError(err)
	s.mu.Unlock()
	signalReady(session)
	s.logger.Warn("oauth authorization failed", "session_id", session.view.ID, "error", redactOAuthError(err))
}

func (s *Service) update(id string, fn func(*oauthSession)) {
	s.mu.Lock()
	if session := s.sessions[id]; session != nil {
		fn(session)
	}
	s.mu.Unlock()
}

func signalReady(session *oauthSession) { session.readyOnce.Do(func() { close(session.ready) }) }
func signalDone(session *oauthSession)  { session.doneOnce.Do(func() { close(session.done) }) }
func vaultID(id string) string          { return "oauth-" + id }

func terminal(status string) bool {
	switch status {
	case "consumed", "not-required", "unsupported", "denied", "failed", "expired", "canceled":
		return true
	default:
		return false
	}
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

var oauthSecretPattern = regexp.MustCompile(`(?i)(access_token|refresh_token|client_secret)(["'=:\s]+)([^\s"'&,}]+)`)

func redactOAuthError(err error) string {
	if err == nil {
		return ""
	}
	value := oauthSecretPattern.ReplaceAllString(err.Error(), "$1$2[redacted]")
	if len(value) > 360 {
		value = value[:360] + "…"
	}
	return value
}
