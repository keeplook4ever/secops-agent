package analyzer

import (
	"context"
	"fmt"
	"log/slog"

	"secops-agent/internal/ingestion"
	"secops-agent/internal/llm"
	"secops-agent/internal/sanitizer"
	"secops-agent/internal/validator"
	"secops-agent/pkg/models"
)

// Analyzer is the central pipeline coordinator. It wires together ingestion,
// sanitization, LLM analysis, and validation into a single Run call.
type Analyzer struct {
	reader     *ingestion.Reader
	classifier *ingestion.Classifier
	sanitizer  *sanitizer.DefaultSanitizer
	llmClient  llm.Client
	validator  *validator.Validator
	logger     *slog.Logger
}

// New creates an Analyzer with the provided LLM client.
func New(llmClient llm.Client, confidenceThreshold float64, logger *slog.Logger) *Analyzer {
	return &Analyzer{
		reader:     ingestion.NewReader(),
		classifier: ingestion.NewClassifier(),
		sanitizer:  sanitizer.New(),
		llmClient:  llmClient,
		validator:  validator.New(confidenceThreshold),
		logger:     logger,
	}
}

// Run executes the full pipeline for a log file and returns the analyzed batches.
func (a *Analyzer) Run(ctx context.Context, logFilePath string) ([]models.AnalyzedBatch, int, error) {
	// --- Stage 1: Ingest ---
	a.logger.Info("ingesting logs", "file", logFilePath)
	rawLogs, err := a.reader.Read(logFilePath)
	if err != nil {
		return nil, 0, fmt.Errorf("analyzer: read: %w", err)
	}
	a.logger.Info("logs loaded", "count", len(rawLogs))

	// --- Stage 2: Classify ---
	classified := a.classifier.Classify(rawLogs)

	// --- Stage 3: Sanitize ---
	sanitized := make([]models.SanitizedLog, 0, len(classified))
	tenantIDByKey := make(map[string]string)
	for _, cl := range classified {
		sl := a.sanitizer.Sanitize(cl)
		sanitized = append(sanitized, sl)
		if cl.Scope == models.ScopeTenant && cl.TenantID != "" {
			tenantIDByKey[sl.TenantKey] = cl.TenantID
		}
	}

	// --- Stage 4: Group into per-tenant batches ---
	batches := a.sanitizer.GroupIntoBatches(sanitized)
	a.logger.Info("batches formed", "count", len(batches))

	// --- Stage 5: Analyze each batch via LLM + validate ---
	results := make([]models.AnalyzedBatch, 0, len(batches))
	for _, batch := range batches {
		analyzed, err := a.analyzeBatch(ctx, batch)
		if err != nil {
			// Log and continue; one bad batch should not abort the whole pipeline.
			a.logger.Error("batch analysis failed", "tenant", batch.TenantKey, "error", err)
			results = append(results, models.AnalyzedBatch{
				TenantKey:        batch.TenantKey,
				TenantID:         tenantIDByKey[batch.TenantKey],
				Scope:            batch.Scope,
				ValidationStatus: models.ValidationSchemaMismatch,
				ValidationNotes:  []string{err.Error()},
			})
			continue
		}
		analyzed.TenantID = tenantIDByKey[batch.TenantKey]
		results = append(results, *analyzed)
	}

	return results, len(rawLogs), nil
}

func (a *Analyzer) analyzeBatch(ctx context.Context, batch models.SanitizedBatch) (*models.AnalyzedBatch, error) {
	a.logger.Info("analyzing batch", "tenant", batch.TenantKey, "logs", len(batch.Logs))

	// Count injection events in this batch before sending to LLM.
	injectionCount := 0
	for _, l := range batch.Logs {
		if l.InjectionDetected {
			injectionCount++
		}
	}

	// Call LLM.
	rawResp, err := a.llmClient.Analyze(ctx, batch)
	if err != nil {
		return nil, fmt.Errorf("llm call: %w", err)
	}

	// Validate response.
	expectedRequestIDs := make([]string, 0, len(batch.Logs))
	for _, l := range batch.Logs {
		expectedRequestIDs = append(expectedRequestIDs, l.OriginalRequestID)
	}

	vr, err := a.validator.Validate(rawResp, batch.TenantKey, expectedRequestIDs)
	if err != nil {
		return nil, fmt.Errorf("validation: %w", err)
	}

	if len(vr.Notes) > 0 {
		a.logger.Warn("validation notes", "tenant", batch.TenantKey, "notes", vr.Notes)
	}

	return &models.AnalyzedBatch{
		TenantKey:        vr.Response.TenantKey,
		Scope:            batch.Scope,
		Findings:         vr.Response.Findings,
		ValidationStatus: vr.Status,
		ValidationNotes:  vr.Notes,
		InjectionCount:   injectionCount,
	}, nil
}
