package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"secops-agent/pkg/models"
)

// Config holds server-specific configuration.
type Config struct {
	Port      int
	OutputDir string
	JWTSecret string
}

// Start loads the incident report from disk and starts the HTTP report server.
// It blocks until the server is stopped.
func Start(cfg Config, logger *slog.Logger) error {
	// Load the global incident report.
	reportPath := filepath.Join(cfg.OutputDir, "incident_report.json")
	report, err := loadReport(reportPath)
	if err != nil {
		return fmt.Errorf("server: load report: %w", err)
	}
	logger.Info("report loaded", "path", reportPath, "tenants", len(report.TenantReports))

	// Open audit log.
	auditPath := filepath.Join(cfg.OutputDir, "audit.log")
	audit, err := NewAuditLogger(auditPath)
	if err != nil {
		return fmt.Errorf("server: audit logger: %w", err)
	}
	defer audit.Close()
	logger.Info("audit log opened", "path", auditPath)

	store := &reportStore{report: report, audit: audit}
	secret := []byte(cfg.JWTSecret)

	mux := http.NewServeMux()

	// Route: list all reports (filtered by RBAC).
	mux.Handle("GET /api/v1/reports", authMiddleware(secret, http.HandlerFunc(store.handleListReports)))

	// Route: get a specific tenant's report.
	// Using a catch-all pattern and extracting tenant_id in the handler.
	mux.Handle("GET /api/v1/reports/", authMiddleware(secret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Distinguish /api/v1/reports (no trailing path) from /api/v1/reports/{id}
		remainder := strings.TrimPrefix(r.URL.Path, "/api/v1/reports/")
		if remainder == "" {
			store.handleListReports(w, r)
			return
		}
		store.handleGetTenantReport(w, r)
	})))

	// Health check (no auth required).
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	addr := fmt.Sprintf(":%d", cfg.Port)
	logger.Info("starting report server", "addr", addr)
	return http.ListenAndServe(addr, mux)
}

func loadReport(path string) (*models.IncidentReport, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	var report models.IncidentReport
	if err := json.NewDecoder(f).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode %q: %w", path, err)
	}
	return &report, nil
}
