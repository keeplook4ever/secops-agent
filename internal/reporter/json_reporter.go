package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"secops-agent/pkg/models"
)

// BuildReport assembles an IncidentReport from the analyzer output.
func BuildReport(analyzedBatches []models.AnalyzedBatch, sourceFile string, totalLogs int, includeInfo bool) *models.IncidentReport {
	report := &models.IncidentReport{
		GeneratedAt: time.Now().UTC(),
		SourceFile:  filepath.Base(sourceFile),
		TotalLogs:   totalLogs,
	}

	for i := range analyzedBatches {
		batch := &analyzedBatches[i]

		filteredFindings := filterFindings(batch.Findings, includeInfo)
		tr := models.TenantReport{
			TenantKey:        batch.TenantKey,
			TenantID:         batch.TenantID,
			Scope:            string(batch.Scope),
			LogCount:         len(filteredFindings),
			Findings:         filteredFindings,
			ValidationStatus: batch.ValidationStatus,
			ValidationNotes:  batch.ValidationNotes,
		}

		for _, f := range batch.Findings {
			switch models.Severity(f.Severity) {
			case models.SeverityCritical:
				report.Summary.CriticalCount++
			case models.SeverityHigh:
				report.Summary.HighCount++
			case models.SeverityMedium:
				report.Summary.MediumCount++
			case models.SeverityLow:
				report.Summary.LowCount++
			case models.SeverityInfo:
				report.Summary.InfoCount++
			}
		}
		report.Summary.InjectionAttemptsDetected += batch.InjectionCount

		if batch.Scope == models.ScopePlatform {
			report.PlatformReport = &tr
		} else {
			report.TenantReports = append(report.TenantReports, tr)
		}
	}

	return report
}

func filterFindings(findings []models.LLMFinding, includeInfo bool) []models.LLMFinding {
	if includeInfo {
		return findings
	}
	filtered := make([]models.LLMFinding, 0, len(findings))
	for _, f := range findings {
		if models.Severity(f.Severity) == models.SeverityInfo {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

// WriteJSON serialises the report to <outputDir>/incident_report.json.
func WriteJSON(report *models.IncidentReport, outputDir string) (string, error) {
	return writeJSONFile(report, outputDir, "incident_report.json")
}

// WritePerTenantJSON writes individual JSON reports into per-tenant subdirectories.
// This implements DESIGN.md Q1-Step4: "reports stored with tenant_id as primary key".
//
// Directory layout:
//
//	output/tenants/<tenant_id>/incident_report.json
//	output/platform/incident_report.json
func WritePerTenantJSON(report *models.IncidentReport, outputDir string) ([]string, error) {
	var paths []string

	for _, tr := range report.TenantReports {
		dirName := tr.TenantID
		if dirName == "" {
			dirName = tr.TenantKey
		}
		tenantDir := filepath.Join(outputDir, "tenants", dirName)
		singleReport := buildSingleTenantReport(report, tr)
		p, err := writeJSONFile(singleReport, tenantDir, "incident_report.json")
		if err != nil {
			return paths, err
		}
		paths = append(paths, p)
	}

	if report.PlatformReport != nil {
		platformDir := filepath.Join(outputDir, "platform")
		singleReport := buildSingleTenantReport(report, *report.PlatformReport)
		p, err := writeJSONFile(singleReport, platformDir, "incident_report.json")
		if err != nil {
			return paths, err
		}
		paths = append(paths, p)
	}

	return paths, nil
}

// buildSingleTenantReport creates a report containing only one tenant's data.
func buildSingleTenantReport(full *models.IncidentReport, tr models.TenantReport) *models.IncidentReport {
	single := &models.IncidentReport{
		GeneratedAt: full.GeneratedAt,
		SourceFile:  full.SourceFile,
		TotalLogs:   tr.LogCount,
	}
	if tr.Scope == "PLATFORM" {
		single.PlatformReport = &tr
	} else {
		single.TenantReports = []models.TenantReport{tr}
	}
	for _, f := range tr.Findings {
		switch models.Severity(f.Severity) {
		case models.SeverityCritical:
			single.Summary.CriticalCount++
		case models.SeverityHigh:
			single.Summary.HighCount++
		case models.SeverityMedium:
			single.Summary.MediumCount++
		case models.SeverityLow:
			single.Summary.LowCount++
		case models.SeverityInfo:
			single.Summary.InfoCount++
		}
	}
	return single
}

func writeJSONFile(v any, dir, filename string) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("reporter: mkdir %q: %w", dir, err)
	}
	outPath := filepath.Join(dir, filename)
	f, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("reporter: create %q: %w", outPath, err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return "", fmt.Errorf("reporter: encode json: %w", err)
	}
	return outPath, nil
}
