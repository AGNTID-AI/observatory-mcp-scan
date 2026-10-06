package oauthflow

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agntid/observatory/api/internal/scanner"
)

func TestDCRPKCEAuthorizationAndOneTimeTokenConsumption(t *testing.T) {
	callbackURL := "http://localhost:3000/api/v1/oauth/callback"
	var mu sync.Mutex
	registered := false
	pkceVerifier := ""
	resourceParameter := ""
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mcp":
			if r.Header.Get("Authorization") != "Bearer fixture-access-token" {
				w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+server.URL+`/.well-known/oauth-protected-resource/mcp", scope="mcp:read"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			var message struct {
				ID     any    `json:"id"`
				Method string `json:"method"`
			}
			_ = json.NewDecoder(r.Body).Decode(&message)
			if message.Method == "notifications/initialized" {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "oauth-fixture-session")
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": message.ID, "result": map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "serverInfo": map[string]any{"name": "OAuth fixture", "version": "1.0.0"}}})
		case "/.well-known/oauth-protected-resource/mcp":
			writeJSON(w, map[string]any{"resource": server.URL + "/mcp", "authorization_servers": []string{server.URL}, "scopes_supported": []string{"mcp:read"}, "bearer_methods_supported": []string{"header"}})
		case "/.well-known/oauth-authorization-server":
			writeJSON(w, map[string]any{"issuer": server.URL, "authorization_endpoint": server.URL + "/authorize", "token_endpoint": server.URL + "/token", "registration_endpoint": server.URL + "/register", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code"}, "code_challenge_methods_supported": []string{"S256"}, "scopes_supported": []string{"mcp:read"}})
		case "/register":
			var metadata map[string]any
			_ = json.NewDecoder(r.Body).Decode(&metadata)
			redirects, _ := metadata["redirect_uris"].([]any)
			if len(redirects) != 1 || redirects[0] != callbackURL || metadata["token_endpoint_auth_method"] != "none" {
				t.Errorf("unexpected registration metadata: %#v", metadata)
			}
			mu.Lock()
			registered = true
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "dynamic-client", "redirect_uris": []string{callbackURL}, "token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code"}, "response_types": []string{"code"}})
		case "/token":
			_ = r.ParseForm()
			mu.Lock()
			pkceVerifier = r.Form.Get("code_verifier")
			resourceParameter = r.Form.Get("resource")
			mu.Unlock()
			writeJSON(w, map[string]any{"access_token": "fixture-access-token", "token_type": "Bearer", "expires_in": 300})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	vault := newMemoryVault()
	service, err := New(scanner.NetworkPolicy{AllowLoopback: true, MaxRedirects: 4, Timeout: 4 * time.Second}, vault, callbackURL, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	view, err := service.Start(context.Background(), server.URL+"/mcp", "Reader")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if view.Status != "awaiting-authorization" || view.AuthorizationURL == "" {
		t.Fatalf("unexpected initial view: %+v", view)
	}
	authorizationURL, err := url.Parse(view.AuthorizationURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	if authorizationURL.Query().Get("code_challenge_method") != "S256" || authorizationURL.Query().Get("resource") != server.URL+"/mcp" {
		t.Fatalf("authorization URL missing PKCE/resource binding: %s", view.AuthorizationURL)
	}
	state := authorizationURL.Query().Get("state")
	if err := service.Complete(state, "fixture-code", "", "", server.URL+"/wrong-issuer"); err == nil {
		t.Fatal("issuer mismatch was accepted")
	}
	if err := service.Complete(state, "fixture-code", "", "", server.URL); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		view, err = service.Get(view.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if view.Status == "authorized" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if view.Status != "authorized" || !view.Profile.AuthorizationCompleted || view.Profile.RegistrationMethod != "dynamic" {
		t.Fatalf("authorization did not complete: %+v", view)
	}
	token, posture, err := service.Consume(context.Background(), view.ID, server.URL+"/mcp", "Reader")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if token != "fixture-access-token" || !posture.DCRSupported || !posture.PKCES256 {
		t.Fatalf("unexpected consumed OAuth result: token=%q posture=%+v", token, posture)
	}
	if _, _, err := service.Consume(context.Background(), view.ID, server.URL+"/mcp", "Reader"); err == nil {
		t.Fatal("OAuth token was consumable more than once")
	}
	mu.Lock()
	defer mu.Unlock()
	if !registered || pkceVerifier == "" || resourceParameter != server.URL+"/mcp" {
		t.Fatalf("DCR/token exchange controls missing: registered=%t verifier=%q resource=%q", registered, pkceVerifier, resourceParameter)
	}
}

func TestRedactOAuthErrorRemovesSecrets(t *testing.T) {
	redacted := redactOAuthError(errors.New(`token exchange failed: {"access_token":"top-secret","client_secret":"also-secret"}`))
	if strings.Contains(redacted, "top-secret") || strings.Contains(redacted, "also-secret") {
		t.Fatalf("OAuth error leaked a secret: %s", redacted)
	}
}

func TestAuthorizedSessionExpiresAndDeletesToken(t *testing.T) {
	vault := newMemoryVault()
	service, err := New(scanner.NetworkPolicy{}, vault, "http://localhost:3000/api/v1/oauth/callback", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	id := "expired-authorized-session"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service.sessions[id] = &oauthSession{
		view:   SessionView{ID: id, Status: "authorized", ExpiresAt: time.Now().Add(-time.Minute)},
		cancel: cancel,
	}
	if err := vault.Put(ctx, vaultID(id), map[string]string{"access_token": "must-be-deleted"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	view, err := service.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if view.Status != "expired" {
		t.Fatalf("status = %q, want expired", view.Status)
	}
	values, _ := vault.Get(ctx, vaultID(id))
	if values["access_token"] != "" {
		t.Fatal("expired OAuth token remained in the vault")
	}
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

type memoryVault struct {
	mu     sync.Mutex
	values map[string]map[string]string
}

func newMemoryVault() *memoryVault { return &memoryVault{values: map[string]map[string]string{}} }

func (v *memoryVault) Put(_ context.Context, id string, values map[string]string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.values[id] = clone(values)
	return nil
}

func (v *memoryVault) Get(_ context.Context, id string) (map[string]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return clone(v.values[id]), nil
}

func (v *memoryVault) Delete(_ context.Context, id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.values, id)
	return nil
}

func clone(values map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range values {
		out[key] = value
	}
	return out
}
