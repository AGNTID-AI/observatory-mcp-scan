package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestInspectOAuthVerifiesDCRPKCEAndResourceMetadata(t *testing.T) {
	serverURL := oauthPostureFixture(t, oauthFixtureOptions{scopes: []string{"mcp:read"}, bearerMethods: []string{"header"}, dcr: true, pkceMethods: []string{"S256"}})
	inspection, err := InspectOAuth(context.Background(), serverURL+"/mcp", NetworkPolicy{AllowLoopback: true, MaxRedirects: 3, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("InspectOAuth: %v", err)
	}
	if !inspection.Profile.Protected || !inspection.Profile.ResourceMetadataValid || !inspection.Profile.AuthorizationServerMetadataValid {
		t.Fatalf("expected verified protected OAuth metadata, got %+v", inspection.Profile)
	}
	if !inspection.Profile.DCRSupported || !inspection.Profile.PKCES256 || !inspection.Profile.HeaderBearerSupported {
		t.Fatalf("expected DCR, PKCE S256, and header bearer support, got %+v", inspection.Profile)
	}
	if got := inspection.Facts["oauth.scopes_advertised"]; got != true {
		t.Fatalf("oauth.scopes_advertised = %v, want true", got)
	}
}

func TestInspectOAuthFlagsUnsafeBearerTransport(t *testing.T) {
	serverURL := oauthPostureFixture(t, oauthFixtureOptions{bearerMethods: []string{"header", "query"}, dcr: true, pkceMethods: []string{"S256"}})
	inspection, err := InspectOAuth(context.Background(), serverURL+"/mcp", NetworkPolicy{AllowLoopback: true, MaxRedirects: 3, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("InspectOAuth: %v", err)
	}
	if got := inspection.Facts["oauth.unsafe_bearer_methods"]; got != true {
		t.Fatalf("oauth.unsafe_bearer_methods = %v, want true", got)
	}
	if got := inspection.Facts["oauth.scopes_advertised"]; got != false {
		t.Fatalf("oauth.scopes_advertised = %v, want false", got)
	}
}

func TestInspectOAuthRecordsMissingProtectedResourceMetadata(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp" {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+server.URL+`/.well-known/oauth-protected-resource/mcp"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	inspection, err := InspectOAuth(context.Background(), server.URL+"/mcp", NetworkPolicy{AllowLoopback: true, MaxRedirects: 3, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("InspectOAuth: %v", err)
	}
	if !inspection.Profile.Protected || inspection.Profile.ResourceMetadataValid {
		t.Fatalf("expected protected endpoint with invalid metadata, got %+v", inspection.Profile)
	}
	if got := inspection.Facts["oauth.resource_metadata_valid"]; got != false {
		t.Fatalf("oauth.resource_metadata_valid = %v, want false", got)
	}
}

type oauthFixtureOptions struct {
	scopes        []string
	bearerMethods []string
	dcr           bool
	pkceMethods   []string
}

func oauthPostureFixture(t *testing.T, options oauthFixtureOptions) string {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mcp":
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+server.URL+`/.well-known/oauth-protected-resource/mcp"`)
			w.WriteHeader(http.StatusUnauthorized)
		case "/.well-known/oauth-protected-resource/mcp":
			writeFixtureJSON(w, map[string]any{"resource": server.URL + "/mcp", "authorization_servers": []string{server.URL}, "scopes_supported": options.scopes, "bearer_methods_supported": options.bearerMethods})
		case "/.well-known/oauth-authorization-server":
			registrationEndpoint := ""
			if options.dcr {
				registrationEndpoint = server.URL + "/register"
			}
			writeFixtureJSON(w, map[string]any{"issuer": server.URL, "authorization_endpoint": server.URL + "/authorize", "token_endpoint": server.URL + "/token", "registration_endpoint": registrationEndpoint, "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code"}, "code_challenge_methods_supported": options.pkceMethods})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func writeFixtureJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
