package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/agntid/observatory/api/internal/domain"
	"github.com/agntid/observatory/api/internal/ports"
	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

type OAuthInspection struct {
	Profile  domain.OAuthPosture
	Facts    map[string]any
	Evidence []domain.Evidence
}

// InspectOAuth evaluates only public challenge and metadata surfaces. It never
// registers a client, opens an authorization page, exchanges a code, or invokes
// an MCP tool.
func InspectOAuth(ctx context.Context, target string, policy NetworkPolicy) (OAuthInspection, error) {
	profile := domain.OAuthPosture{
		Status: "not-protected", AuthorizationServers: []string{}, Scopes: []string{},
		BearerMethods: []string{}, AuthorizedIdentities: []string{}, Diagnostics: []string{},
		AssessedAt: time.Now().UTC(),
	}
	client, targetURL, err := policy.Client(ctx, target, nil)
	if err != nil {
		return OAuthInspection{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL.String(), strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"observatory-oauth-posture","version":"0.3.0"}}}`))
	if err != nil {
		return OAuthInspection{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		return OAuthInspection{}, err
	}
	resp.Body.Close()
	profile.Protected = resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden
	challenges, parseErr := oauthex.ParseWWWAuthenticate(resp.Header.Values("WWW-Authenticate"))
	if parseErr != nil {
		profile.Diagnostics = append(profile.Diagnostics, "WWW-Authenticate could not be parsed: "+safeDiagnostic(parseErr))
	}
	profile.ChallengePresent = len(challenges) > 0
	if !profile.Protected {
		facts := oauthFacts(profile)
		ev := Evidence("oauth-posture", "oauth-posture", "OAuth boundary assessed", fmt.Sprintf("Anonymous initialization returned HTTP %d; an OAuth challenge was not required", resp.StatusCode), "measured", facts)
		return OAuthInspection{Profile: profile, Facts: facts, Evidence: []domain.Evidence{ev}}, nil
	}

	profile.Status = "protected"
	challengeMetadataURL := ""
	for _, challenge := range challenges {
		if challenge.Scheme != "bearer" {
			continue
		}
		if challengeMetadataURL == "" {
			challengeMetadataURL = challenge.Params["resource_metadata"]
		}
		if scope := challenge.Params["scope"]; scope != "" {
			profile.Scopes = compactStrings(append(profile.Scopes, strings.Fields(scope)...))
		}
	}

	var prm *oauthex.ProtectedResourceMetadata
	for _, candidate := range protectedResourceCandidates(targetURL, challengeMetadataURL) {
		candidateClient, _, clientErr := policy.Client(ctx, candidate.MetadataURL, nil)
		if clientErr != nil {
			profile.Diagnostics = append(profile.Diagnostics, safeDiagnostic(clientErr))
			continue
		}
		metadata, fetchErr := oauthex.GetProtectedResourceMetadata(ctx, candidate.MetadataURL, candidate.Resource, candidateClient)
		if fetchErr != nil {
			profile.Diagnostics = append(profile.Diagnostics, safeDiagnostic(fetchErr))
			continue
		}
		prm = metadata
		profile.ResourceMetadataURL = candidate.MetadataURL
		break
	}
	if prm == nil {
		profile.Status = "metadata-incomplete"
		facts := oauthFacts(profile)
		ev := Evidence("oauth-posture", "oauth-posture", "OAuth metadata is incomplete", "The endpoint requires authorization, but valid protected-resource metadata could not be verified", "measured", facts)
		return OAuthInspection{Profile: profile, Facts: facts, Evidence: []domain.Evidence{ev}}, nil
	}

	profile.ResourceMetadataValid = true
	profile.Resource = prm.Resource
	profile.AuthorizationServers = append([]string(nil), prm.AuthorizationServers...)
	profile.Scopes = compactStrings(append(profile.Scopes, prm.ScopesSupported...))
	profile.BearerMethods = append([]string(nil), prm.BearerMethodsSupported...)
	profile.HeaderBearerSupported = len(profile.BearerMethods) == 0 || slices.Contains(profile.BearerMethods, "header")
	if len(prm.AuthorizationServers) == 0 {
		profile.Status = "metadata-incomplete"
		profile.Diagnostics = append(profile.Diagnostics, "Protected-resource metadata does not advertise an authorization server")
	} else {
		issuer := prm.AuthorizationServers[0]
		profile.Issuer = issuer
		authClient, _, clientErr := policy.Client(ctx, issuer, nil)
		if clientErr != nil {
			profile.Diagnostics = append(profile.Diagnostics, safeDiagnostic(clientErr))
		} else {
			metadata, metadataErr := mcpauth.GetAuthServerMetadata(ctx, issuer, authClient)
			if metadataErr != nil {
				profile.Diagnostics = append(profile.Diagnostics, safeDiagnostic(metadataErr))
			} else if metadata == nil {
				profile.Diagnostics = append(profile.Diagnostics, "Authorization-server metadata was not found")
			} else {
				applyAuthorizationMetadata(&profile, metadata)
			}
		}
	}
	if profile.ResourceMetadataValid && profile.AuthorizationServerMetadataValid {
		profile.Status = "ready"
	} else {
		profile.Status = "metadata-incomplete"
	}
	facts := oauthFacts(profile)
	summary := "OAuth is required and its discovery metadata was assessed"
	if profile.Status != "ready" {
		summary = "OAuth is required, but one or more discovery or security controls could not be verified"
	}
	ev := Evidence("oauth-posture", "oauth-posture", "OAuth security posture assessed", summary, "measured", facts)
	return OAuthInspection{Profile: profile, Facts: facts, Evidence: []domain.Evidence{ev}}, nil
}

type protectedResourceCandidate struct{ MetadataURL, Resource string }

func protectedResourceCandidates(resourceURL *url.URL, challengeURL string) []protectedResourceCandidate {
	result := []protectedResourceCandidate{}
	if strings.TrimSpace(challengeURL) != "" {
		result = append(result, protectedResourceCandidate{MetadataURL: challengeURL, Resource: resourceURL.String()})
	}
	pathURL := *resourceURL
	pathURL.Path = "/.well-known/oauth-protected-resource/" + strings.TrimLeft(resourceURL.Path, "/")
	pathURL.RawQuery, pathURL.Fragment = "", ""
	result = append(result, protectedResourceCandidate{MetadataURL: pathURL.String(), Resource: resourceURL.String()})
	rootURL := *resourceURL
	rootURL.Path, rootURL.RawPath, rootURL.RawQuery, rootURL.Fragment = "", "", "", ""
	metadataURL := rootURL
	metadataURL.Path = "/.well-known/oauth-protected-resource"
	result = append(result, protectedResourceCandidate{MetadataURL: metadataURL.String(), Resource: rootURL.String()})
	return uniqueCandidates(result)
}

func uniqueCandidates(values []protectedResourceCandidate) []protectedResourceCandidate {
	seen := map[string]bool{}
	out := make([]protectedResourceCandidate, 0, len(values))
	for _, value := range values {
		key := value.MetadataURL + "\x00" + value.Resource
		if value.MetadataURL == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	return out
}

func applyAuthorizationMetadata(profile *domain.OAuthPosture, metadata *oauthex.AuthServerMeta) {
	profile.AuthorizationServerMetadataValid = true
	profile.Issuer = metadata.Issuer
	profile.AuthorizationEndpoint = metadata.AuthorizationEndpoint
	profile.TokenEndpoint = metadata.TokenEndpoint
	profile.RegistrationEndpoint = metadata.RegistrationEndpoint
	profile.DCRSupported = metadata.RegistrationEndpoint != ""
	profile.ClientIDMetadataDocumentSupported = metadata.ClientIDMetadataDocumentSupported
	profile.PKCES256 = slices.Contains(metadata.CodeChallengeMethodsSupported, "S256")
	profile.Scopes = compactStrings(append(profile.Scopes, metadata.ScopesSupported...))
}

func oauthFacts(profile domain.OAuthPosture) map[string]any {
	unsafeBearer := slices.Contains(profile.BearerMethods, "query") || slices.Contains(profile.BearerMethods, "body")
	return map[string]any{
		"oauth.detected":                              profile.Protected,
		"oauth.challenge_present":                     profile.ChallengePresent,
		"oauth.resource_metadata_valid":               profile.ResourceMetadataValid,
		"oauth.authorization_server_metadata_valid":   profile.AuthorizationServerMetadataValid,
		"oauth.pkce_s256":                             profile.PKCES256,
		"oauth.dcr_supported":                         profile.DCRSupported,
		"oauth.client_id_metadata_document_supported": profile.ClientIDMetadataDocumentSupported,
		"oauth.header_bearer_supported":               profile.HeaderBearerSupported,
		"oauth.unsafe_bearer_methods":                 unsafeBearer,
		"oauth.scopes_advertised":                     len(profile.Scopes) > 0,
		"oauth.authorization_server_count":            len(profile.AuthorizationServers),
		"oauth.authorization_completed":               profile.AuthorizationCompleted,
	}
}

func safeDiagnostic(err error) string {
	value := strings.TrimSpace(err.Error())
	if len(value) > 240 {
		return value[:240] + "…"
	}
	return value
}

func (e StageEngine) oauthPosture(ctx context.Context, ec ports.EngineContext) (ports.EngineResult, error) {
	inspection, err := InspectOAuth(ctx, ec.Assessment.Target.URL, e.Policy)
	if err != nil {
		return ports.EngineResult{}, err
	}
	inspection.Profile.AuthorizationCompleted = ec.Assessment.OAuth.AuthorizationCompleted
	inspection.Profile.RegistrationMethod = ec.Assessment.OAuth.RegistrationMethod
	inspection.Profile.AuthorizedIdentities = append([]string(nil), ec.Assessment.OAuth.AuthorizedIdentities...)
	inspection.Facts["oauth.authorization_completed"] = inspection.Profile.AuthorizationCompleted
	return ports.EngineResult{Facts: inspection.Facts, Evidence: inspection.Evidence, OAuth: &inspection.Profile}, nil
}
