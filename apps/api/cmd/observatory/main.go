package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/agntid/observatory/api/internal/httpapi"
	"github.com/agntid/observatory/api/internal/oauthflow"
	"github.com/agntid/observatory/api/internal/ports"
	"github.com/agntid/observatory/api/internal/reporting"
	"github.com/agntid/observatory/api/internal/rules"
	"github.com/agntid/observatory/api/internal/scanner"
	"github.com/agntid/observatory/api/internal/service"
	"github.com/agntid/observatory/api/internal/storage"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	dataDir := env("OBSERVATORY_DATA_DIR", "./data")
	store, err := storage.Open(filepath.Join(dataDir, "observatory.db"), filepath.Join(dataDir, "credential.key"), os.Getenv("OBSERVATORY_CREDENTIAL_KEY"))
	if err != nil {
		logger.Error("open store", "error", err)
		os.Exit(1)
	}
	// Pending OAuth browser workflows are intentionally process-local. Remove
	// any encrypted token left by an interrupted flow before accepting traffic.
	if err := store.DeleteCredentialPrefix(context.Background(), "oauth-"); err != nil {
		logger.Error("remove interrupted OAuth credentials", "error", err)
		os.Exit(1)
	}
	ruleDir := env("OBSERVATORY_RULE_DIR", "../../rules/public")
	evaluator, err := rules.Load(ruleDir)
	if err != nil {
		logger.Error("load rules", "error", err, "dir", ruleDir)
		os.Exit(1)
	}
	artifactStore := storage.FileArtifacts{Root: filepath.Join(dataDir, "artifacts")}
	policy := scanner.NetworkPolicy{AllowLoopback: envBool("OBSERVATORY_ALLOW_LOOPBACK", false), MaxRedirects: 5, Timeout: 30 * time.Second}
	engines := []ports.Engine{scanner.StageEngine{StageID: "discovery", StageName: "Discovery", Policy: policy}, scanner.StageEngine{StageID: "transport", StageName: "Transport Validation", Policy: policy}, scanner.StageEngine{StageID: "authentication", StageName: "Authentication Assessment", Policy: policy}, scanner.StageEngine{StageID: "oauth-posture", StageName: "OAuth Security Posture", Policy: policy}, scanner.StageEngine{StageID: "authorization", StageName: "Authorization Assessment", Policy: policy}, scanner.StageEngine{StageID: "protocol", StageName: "Protocol Compliance", Policy: policy}, scanner.StageEngine{StageID: "tool-discovery", StageName: "Tool Discovery", Policy: policy}, scanner.StageEngine{StageID: "tool-classification", StageName: "Tool Classification", Policy: policy}, scanner.StageEngine{StageID: "content-integrity", StageName: "Metadata Content Integrity", Policy: policy}, scanner.StageEngine{StageID: "contract-readiness", StageName: "Tool Contract Readiness", Policy: policy}, scanner.StageEngine{StageID: "ai-readiness", StageName: "AI Readiness Analysis", Policy: policy}, scanner.StageEngine{StageID: "operational", StageName: "Operational Checks", Policy: policy}, scanner.StageEngine{StageID: "catalog-drift", StageName: "Catalog Drift", Policy: policy}}
	vault := storage.Vault{Store: store}
	oauthService, err := oauthflow.New(policy, vault, env("OBSERVATORY_OAUTH_CALLBACK_URL", "http://localhost:3000/api/v1/oauth/callback"), logger)
	if err != nil {
		logger.Error("configure OAuth", "error", err)
		os.Exit(1)
	}
	manager := service.NewManager(store, store, vault, evaluator, reporting.Generator{Store: artifactStore}, engines, envInt("OBSERVATORY_WORKERS", 2), logger)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	manager.Start(ctx)
	seed(manager, store, logger)
	handler := httpapi.New(manager, store, artifactStore, oauthService, logger).Handler()
	server := &http.Server{Addr: env("OBSERVATORY_LISTEN", ":8080"), Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		logger.Info("observatory api listening", "address", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server stopped", "error", err)
			cancel()
		}
	}()
	<-ctx.Done()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
}
func seed(manager *service.Manager, store *storage.Store, logger *slog.Logger) {
	items, err := store.List(context.Background(), 1, "")
	if err != nil || len(items) > 0 {
		return
	}
	_, err = manager.Create(context.Background(), service.CreateInput{Mode: "sample", URL: "https://acme-mcp.example.com/mcp"})
	if err != nil {
		logger.Warn("seed sample assessment", "error", err)
	}
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func envBool(k string, d bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return d
	}
	return b
}
func envInt(k string, d int) int {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return d
	}
	return n
}
