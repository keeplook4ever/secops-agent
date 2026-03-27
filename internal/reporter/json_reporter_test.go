package reporter

import (
	"testing"

	"github.com/wati/secops-agent/pkg/models"
)

func TestBuildReport_ExcludeInfoFindings(t *testing.T) {
	batches := []models.AnalyzedBatch{
		{
			TenantKey: "TENANT_ID_1",
			Scope:     models.ScopeTenant,
			Findings: []models.LLMFinding{
				{RequestID: "r1", Severity: "INFO"},
				{RequestID: "r2", Severity: "HIGH"},
			},
		},
	}

	report := BuildReport(batches, "sample.json", 2, false)
	if len(report.TenantReports) != 1 {
		t.Fatalf("expected one tenant report, got %d", len(report.TenantReports))
	}
	if got := len(report.TenantReports[0].Findings); got != 1 {
		t.Fatalf("expected only non-info finding, got %d", got)
	}
	if report.TenantReports[0].Findings[0].RequestID != "r2" {
		t.Fatalf("expected high finding to remain, got %s", report.TenantReports[0].Findings[0].RequestID)
	}
	if report.Summary.InfoCount != 1 {
		t.Fatalf("expected info count 1 in summary even when details excluded, got %d", report.Summary.InfoCount)
	}
}

func TestBuildReport_IncludeInfoFindings(t *testing.T) {
	batches := []models.AnalyzedBatch{
		{
			TenantKey: "TENANT_ID_1",
			Scope:     models.ScopeTenant,
			Findings: []models.LLMFinding{
				{RequestID: "r1", Severity: "INFO"},
				{RequestID: "r2", Severity: "HIGH"},
			},
		},
	}

	report := BuildReport(batches, "sample.json", 2, true)
	if got := len(report.TenantReports[0].Findings); got != 2 {
		t.Fatalf("expected all findings, got %d", got)
	}
	if report.Summary.InfoCount != 1 {
		t.Fatalf("expected info count 1, got %d", report.Summary.InfoCount)
	}
}
