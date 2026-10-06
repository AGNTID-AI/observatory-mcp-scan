package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/agntid/observatory/api/internal/domain"
	"github.com/agntid/observatory/api/internal/oauthflow"
	"github.com/agntid/observatory/api/internal/service"
	"github.com/agntid/observatory/api/internal/storage"
	"github.com/google/uuid"
)

type Server struct {
	manager   *service.Manager
	events    *storage.Store
	artifacts storage.FileArtifacts
	oauth     *oauthflow.Service
	logger    *slog.Logger
}

func New(manager *service.Manager, events *storage.Store, artifacts storage.FileArtifacts, oauth *oauthflow.Service, logger *slog.Logger) *Server {
	return &Server{manager: manager, events: events, artifacts: artifacts, oauth: oauth, logger: logger}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { jsonResponse(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, 200, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("GET /api/v1/dashboard/summary", s.dashboard)
	mux.HandleFunc("GET /api/v1/rules", s.listRules)
	mux.HandleFunc("GET /api/v1/settings", s.settings)
	mux.HandleFunc("POST /api/v1/oauth/sessions", s.createOAuthSession)
	mux.HandleFunc("GET /api/v1/oauth/sessions/{id}", s.getOAuthSession)
	mux.HandleFunc("POST /api/v1/oauth/sessions/{id}/cancel", s.cancelOAuthSession)
	mux.HandleFunc("GET /api/v1/oauth/callback", s.oauthCallback)
	mux.HandleFunc("GET /api/v1/assessments", s.listAssessments)
	mux.HandleFunc("POST /api/v1/assessments", s.createAssessment)
	mux.HandleFunc("/api/v1/assessments/", s.assessmentRoutes)
	return s.middleware(mux)
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", requestID)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		start := time.Now()
		next.ServeHTTP(w, r)
		s.logger.Info("request", "method", r.Method, "path", r.URL.Path, "request_id", requestID, "duration_ms", time.Since(start).Milliseconds())
	})
}

type createRequest struct {
	Mode   string `json:"mode"`
	Target struct {
		Protocol string `json:"protocol"`
		URL      string `json:"url"`
	} `json:"target"`
	Credentials *struct {
		BearerToken string            `json:"bearerToken"`
		Headers     map[string]string `json:"headers"`
	} `json:"credentials,omitempty"`
	CredentialProfiles []struct {
		Label          string            `json:"label"`
		BearerToken    string            `json:"bearerToken"`
		Headers        map[string]string `json:"headers"`
		OAuthSessionID string            `json:"oauthSessionId"`
	} `json:"credentialProfiles,omitempty"`
	Snapshot *domain.OfflineSnapshot `json:"snapshot,omitempty"`
}

func (s *Server) createAssessment(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if err := decodeJSON(r.Body, &req); err != nil {
		problem(w, 400, "Invalid request", err.Error())
		return
	}
	if req.Mode == "offline" {
		if req.Snapshot == nil {
			problem(w, 400, "Snapshot required", "Offline mode requires a metadata snapshot.")
			return
		}
		if len(req.Snapshot.Tools) > 1000 || len(req.Snapshot.Prompts)+len(req.Snapshot.Resources) > 1000 {
			problem(w, 413, "Snapshot too large", "A snapshot may contain at most 1,000 tools and 1,000 prompt/resource items.")
			return
		}
		toolNames := map[string]bool{}
		for _, tool := range req.Snapshot.Tools {
			name := strings.TrimSpace(tool.Name)
			if name == "" {
				problem(w, 400, "Invalid snapshot", "Every imported tool requires a name.")
				return
			}
			key := strings.ToLower(name)
			if toolNames[key] {
				problem(w, 400, "Invalid snapshot", "Imported tool names must be unique.")
				return
			}
			toolNames[key] = true
		}
		if strings.TrimSpace(req.Target.URL) == "" {
			host := snapshotHost(req.Snapshot.Name)
			req.Target.URL = "snapshot://" + host
		}
		if strings.TrimSpace(req.Snapshot.TargetURL) != "" {
			req.Target.URL = req.Snapshot.TargetURL
		}
		if len(req.CredentialProfiles) > 0 || req.Credentials != nil {
			problem(w, 400, "Credentials not accepted", "Offline snapshots cannot include scan credentials.")
			return
		}
	}
	token := ""
	headers := map[string]string{}
	if req.Credentials != nil {
		token = req.Credentials.BearerToken
		headers = req.Credentials.Headers
	}
	for k := range headers {
		if !allowedCustomHeader(k) {
			problem(w, 400, "Unsafe header", "The custom header "+k+" is not permitted.")
			return
		}
	}
	profiles := make([]service.CredentialProfileInput, 0, len(req.CredentialProfiles))
	var oauthProfile *domain.OAuthPosture
	labels := map[string]bool{}
	for _, profile := range req.CredentialProfiles {
		label := strings.TrimSpace(profile.Label)
		if label == "" {
			problem(w, 400, "Invalid credential profile", "Every credential profile requires a label.")
			return
		}
		key := strings.ToLower(label)
		if labels[key] || key == "anonymous" {
			problem(w, 400, "Invalid credential profile", "Credential profile labels must be unique and cannot be Anonymous.")
			return
		}
		labels[key] = true
		for header := range profile.Headers {
			if !allowedCustomHeader(header) {
				problem(w, 400, "Unsafe header", "The custom header "+header+" is not permitted.")
				return
			}
		}
		if strings.TrimSpace(profile.BearerToken) == "" && len(profile.Headers) == 0 && strings.TrimSpace(profile.OAuthSessionID) == "" {
			problem(w, 400, "Invalid credential profile", "Credential profile "+label+" does not contain a bearer token or custom header.")
			return
		}
		if strings.TrimSpace(profile.OAuthSessionID) != "" {
			if strings.TrimSpace(profile.BearerToken) != "" || len(profile.Headers) > 0 {
				problem(w, 400, "Ambiguous credential profile", "Choose either an OAuth connection or manually supplied credentials for "+label+".")
				return
			}
			accessToken, posture, err := s.oauth.Consume(r.Context(), profile.OAuthSessionID, req.Target.URL, label)
			if err != nil {
				problem(w, 422, "OAuth credential unavailable", err.Error())
				return
			}
			profile.BearerToken = accessToken
			if oauthProfile == nil {
				copy := posture
				oauthProfile = &copy
			}
			oauthProfile.AuthorizationCompleted = true
			oauthProfile.RegistrationMethod = posture.RegistrationMethod
			oauthProfile.AuthorizedIdentities = appendUnique(oauthProfile.AuthorizedIdentities, label)
		}
		profiles = append(profiles, service.CredentialProfileInput{Label: label, BearerToken: profile.BearerToken, Headers: profile.Headers})
	}
	a, err := s.manager.Create(r.Context(), service.CreateInput{Mode: req.Mode, URL: req.Target.URL, BearerToken: token, Headers: headers, CredentialProfiles: profiles, Snapshot: req.Snapshot, OAuth: oauthProfile})
	if err != nil {
		problem(w, 422, "Assessment could not be queued", err.Error())
		return
	}
	w.Header().Set("Location", "/api/v1/assessments/"+a.ID)
	jsonResponse(w, 202, map[string]any{"assessmentId": a.ID, "status": a.Status, "eventsUrl": "/api/v1/assessments/" + a.ID + "/events"})
}

func snapshotHost(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else if b.Len() > 0 {
			b.WriteByte('-')
		}
	}
	result := strings.Trim(b.String(), "-")
	if result == "" {
		return "imported-catalog"
	}
	return result
}
func allowedCustomHeader(k string) bool {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "host", "connection", "content-length", "transfer-encoding", "forwarded", "x-forwarded-for", "x-forwarded-host", "proxy-authorization", "cookie", "authorization":
		return false
	}
	return strings.TrimSpace(k) != ""
}
func (s *Server) listAssessments(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.manager.List(r.Context(), limit, r.URL.Query().Get("cursor"))
	if err != nil {
		problem(w, 500, "List failed", err.Error())
		return
	}
	jsonResponse(w, 200, map[string]any{"items": items, "nextCursor": ""})
}
func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	data, err := s.manager.Dashboard(r.Context())
	if err != nil {
		problem(w, 500, "Dashboard unavailable", err.Error())
		return
	}
	jsonResponse(w, 200, data)
}
func (s *Server) listRules(w http.ResponseWriter, _ *http.Request) {
	jsonResponse(w, 200, map[string]any{"items": s.manager.Rules()})
}
func (s *Server) settings(w http.ResponseWriter, _ *http.Request) {
	jsonResponse(w, 200, map[string]any{"workspaceMode": "single", "toolInvocation": false, "interactiveOAuth": true, "dynamicClientRegistration": true, "oauthPKCE": "S256", "identityComparison": true, "offlineSnapshots": true, "sarifArtifacts": true, "catalogDrift": true, "networkPolicy": map[string]any{"publicTargets": true, "privateTargets": true, "loopbackTargets": false, "linkLocalTargets": false, "maxRedirects": 5}, "limits": map[string]any{"concurrentAssessments": 2, "assessmentTimeoutSeconds": 300, "stageTimeoutSeconds": 30, "maxResponseBytes": 5242880, "maxItems": 1000, "maxCredentialProfiles": 4}})
}

func (s *Server) createOAuthSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetURL string `json:"targetUrl"`
		Label     string `json:"label"`
	}
	if err := decodeJSON(r.Body, &req); err != nil {
		problem(w, 400, "Invalid request", err.Error())
		return
	}
	view, err := s.oauth.Start(r.Context(), strings.TrimSpace(req.TargetURL), strings.TrimSpace(req.Label))
	if err != nil {
		problem(w, 422, "OAuth discovery failed", err.Error())
		return
	}
	jsonResponse(w, 201, view)
}

func (s *Server) getOAuthSession(w http.ResponseWriter, r *http.Request) {
	view, err := s.oauth.Get(r.PathValue("id"))
	if errors.Is(err, oauthflow.ErrNotFound) {
		problem(w, 404, "OAuth session not found", "The authorization session is unavailable or expired.")
		return
	}
	if err != nil {
		problem(w, 500, "OAuth session unavailable", err.Error())
		return
	}
	jsonResponse(w, 200, view)
}

func (s *Server) cancelOAuthSession(w http.ResponseWriter, r *http.Request) {
	if err := s.oauth.Cancel(r.PathValue("id")); err != nil {
		problem(w, 404, "OAuth session not found", "The authorization session is unavailable or expired.")
		return
	}
	jsonResponse(w, 202, map[string]string{"status": "canceled"})
}

func (s *Server) oauthCallback(w http.ResponseWriter, r *http.Request) {
	err := s.oauth.Complete(r.URL.Query().Get("state"), r.URL.Query().Get("code"), r.URL.Query().Get("error"), r.URL.Query().Get("error_description"), r.URL.Query().Get("iss"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, oauthCallbackPage(false))
		return
	}
	_, _ = io.WriteString(w, oauthCallbackPage(true))
}

func oauthCallbackPage(success bool) string {
	title, detail, color := "Authorization could not be completed", "Return to Observatory and start a new OAuth connection.", "#b42335"
	if success {
		title, detail, color = "Authorization received", "Observatory is securely exchanging the authorization code. You can close this window.", "#177a55"
	}
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>AgntID Observatory OAuth</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f6fb;color:#102238;font:15px/1.5 system-ui}.card{max-width:460px;margin:24px;padding:30px;border:1px solid #dbe3ec;border-radius:16px;background:white;box-shadow:0 18px 50px #10223812}.mark{width:42px;height:42px;display:grid;place-items:center;border-radius:50%;background:` + color + `18;color:` + color + `;font-size:24px;font-weight:800}h1{font-size:22px;margin:18px 0 8px}p{color:#607086}</style></head><body><main class="card"><div class="mark">` + map[bool]string{true: "✓", false: "!"}[success] + `</div><h1>` + title + `</h1><p>` + detail + `</p></main></body></html>`
}

func appendUnique(values []string, value string) []string {
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
}

func (s *Server) assessmentRoutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/assessments/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		problem(w, 404, "Not found", "")
		return
	}
	id := parts[0]
	if len(parts) == 1 && r.Method == http.MethodGet {
		s.getAssessment(w, r, id)
		return
	}
	if len(parts) == 2 && parts[1] == "cancel" && r.Method == http.MethodPost {
		s.cancelAssessment(w, r, id)
		return
	}
	if len(parts) == 2 && parts[1] == "events" && r.Method == http.MethodGet {
		s.streamEvents(w, r, id)
		return
	}
	if len(parts) == 3 && parts[1] == "artifacts" && r.Method == http.MethodGet {
		s.downloadArtifact(w, r, id, parts[2])
		return
	}
	problem(w, 404, "Not found", "The requested assessment resource does not exist.")
}
func (s *Server) getAssessment(w http.ResponseWriter, r *http.Request, id string) {
	a, err := s.manager.Get(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		problem(w, 404, "Assessment not found", id)
		return
	}
	if err != nil {
		problem(w, 500, "Assessment unavailable", err.Error())
		return
	}
	jsonResponse(w, 200, a)
}
func (s *Server) cancelAssessment(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.manager.Cancel(r.Context(), id); err != nil {
		problem(w, 500, "Cancellation failed", err.Error())
		return
	}
	jsonResponse(w, 202, map[string]string{"status": "cancel-requested"})
}

func (s *Server) streamEvents(w http.ResponseWriter, r *http.Request, id string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		problem(w, 500, "Streaming unsupported", "")
		return
	}
	after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	if header := r.Header.Get("Last-Event-ID"); header != "" {
		if n, err := strconv.ParseUint(header, 10, 64); err == nil && n > after {
			after = n
		}
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	ticker := time.NewTicker(750 * time.Millisecond)
	defer ticker.Stop()
	for {
		events, err := s.events.ListAfter(r.Context(), id, after)
		if err != nil {
			return
		}
		for _, event := range events {
			fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", event.ID, event.Type, event.Data)
			after = event.ID
			flusher.Flush()
		}
		a, err := s.manager.Get(r.Context(), id)
		if err != nil {
			return
		}
		if a.Status == "completed" || a.Status == "partial" || a.Status == "failed" || a.Status == "canceled" {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}
func (s *Server) downloadArtifact(w http.ResponseWriter, r *http.Request, id, artifactID string) {
	reader, artifact, err := s.artifacts.Open(r.Context(), id, artifactID)
	if errors.Is(err, storage.ErrNotFound) {
		problem(w, 404, "Artifact not found", artifactID)
		return
	}
	if err != nil {
		problem(w, 500, "Artifact unavailable", err.Error())
		return
	}
	defer reader.Close()
	w.Header().Set("Content-Type", artifact.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", artifact.Name))
	if strings.HasSuffix(artifact.Name, ".html") {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:")
	}
	_, _ = io.Copy(w, reader)
}

func decodeJSON(r io.Reader, v any) error {
	dec := json.NewDecoder(io.LimitReader(r, 5<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func problem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "title": title, "status": status, "detail": detail})
}

func Shutdown(ctx context.Context, server *http.Server) error { return server.Shutdown(ctx) }
