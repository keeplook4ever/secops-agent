package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"secops-agent/pkg/models"
)

// WriteMarkdown generates a human-readable Markdown incident report.
func WriteMarkdown(report *models.IncidentReport, outputDir string) (string, error) {
	return writeMDFile(report, outputDir)
}

// WritePerTenantMarkdown writes individual Markdown reports into per-tenant subdirectories.
func WritePerTenantMarkdown(report *models.IncidentReport, outputDir string) ([]string, error) {
	var paths []string

	for _, tr := range report.TenantReports {
		dirName := tr.TenantID
		if dirName == "" {
			dirName = tr.TenantKey
		}
		tenantDir := filepath.Join(outputDir, "tenants", dirName)
		singleReport := buildSingleTenantReport(report, tr)
		p, err := writeMDFile(singleReport, tenantDir)
		if err != nil {
			return paths, err
		}
		paths = append(paths, p)
	}

	if report.PlatformReport != nil {
		platformDir := filepath.Join(outputDir, "platform")
		singleReport := buildSingleTenantReport(report, *report.PlatformReport)
		p, err := writeMDFile(singleReport, platformDir)
		if err != nil {
			return paths, err
		}
		paths = append(paths, p)
	}

	return paths, nil
}

func writeMDFile(report *models.IncidentReport, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return "", fmt.Errorf("reporter: mkdir %q: %w", outputDir, err)
	}

	outPath := filepath.Join(outputDir, "incident_summary.md")
	f, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("reporter: create %q: %w", outPath, err)
	}
	defer f.Close()

	w := &mdWriter{f}
	writeMarkdownContent(w, report)

	if err := f.Close(); err != nil {
		return "", fmt.Errorf("reporter: close: %w", err)
	}
	return outPath, nil
}

func writeMarkdownContent(w *mdWriter, r *models.IncidentReport) {
	w.h1("SecOps Buddy Agent — Incident Report")
	w.kv("Generated", r.GeneratedAt.Format(time.RFC3339))
	w.kv("Source File", r.SourceFile)
	w.kv("Total Logs Analysed", fmt.Sprintf("%d", r.TotalLogs))
	w.ln()

	// --- Executive Summary ---
	w.h2("Executive Summary")
	w.tableHeader("Severity", "Count")
	w.tableRow("🔴 CRITICAL", fmt.Sprintf("%d", r.Summary.CriticalCount))
	w.tableRow("🟠 HIGH", fmt.Sprintf("%d", r.Summary.HighCount))
	w.tableRow("🟡 MEDIUM", fmt.Sprintf("%d", r.Summary.MediumCount))
	w.tableRow("🟢 LOW", fmt.Sprintf("%d", r.Summary.LowCount))
	w.tableRow("⚪ INFO", fmt.Sprintf("%d", r.Summary.InfoCount))
	w.tableRow("💉 Injection Attempts Detected", fmt.Sprintf("%d", r.Summary.InjectionAttemptsDetected))
	w.ln()

	// --- Tenant Reports ---
	w.h2("Tenant Reports")
	for _, tr := range r.TenantReports {
		writeTenantSection(w, tr)
	}

	// --- Platform Report ---
	if r.PlatformReport != nil {
		w.h2("Platform (Infrastructure) Report")
		writeTenantSection(w, *r.PlatformReport)
	}
}

func writeTenantSection(w *mdWriter, tr models.TenantReport) {
	w.h3(fmt.Sprintf("Scope: %s | Key: %s", tr.Scope, tr.TenantKey))
	if tr.TenantID != "" {
		w.kv("Tenant ID", tr.TenantID)
	}
	w.kv("Log Count", fmt.Sprintf("%d", tr.LogCount))
	w.kv("Validation Status", string(tr.ValidationStatus))
	if len(tr.ValidationNotes) > 0 {
		w.kv("Validation Notes", strings.Join(tr.ValidationNotes, "; "))
	}
	w.ln()

	if len(tr.Findings) == 0 {
		w.italic("No findings.")
		w.ln()
		return
	}

	for _, f := range tr.Findings {
		writeFinding(w, f)
	}
}

func writeFinding(w *mdWriter, f models.LLMFinding) {
	severityIcon := severityEmoji(f.Severity)
	w.h4(fmt.Sprintf("%s [%s] %s — %s", severityIcon, f.Severity, f.RequestID, f.AttackPattern))

	w.tableHeader("Field", "Value")
	w.tableRow("Request ID", f.RequestID)
	w.tableRow("Attack Pattern", f.AttackPattern)
	w.tableRow("Description", f.Description)
	w.tableRow("SOC 2 Controls", strings.Join(f.SOC2Controls, ", "))
	if len(f.CVEs) > 0 {
		w.tableRow("CVEs", strings.Join(f.CVEs, ", "))
	}
	w.tableRow("Confidence", fmt.Sprintf("%.0f%%", f.ConfidenceScore*100))
	w.tableRow("Remediation", f.Remediation)
	w.ln()
}

func severityEmoji(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return "🔴"
	case "HIGH":
		return "🟠"
	case "MEDIUM":
		return "🟡"
	case "LOW":
		return "🟢"
	default:
		return "⚪"
	}
}

// mdWriter is a thin helper for writing Markdown to a file.
type mdWriter struct {
	f *os.File
}

func (w *mdWriter) write(s string) { fmt.Fprint(w.f, s) }
func (w *mdWriter) ln()            { fmt.Fprintln(w.f) }
func (w *mdWriter) h1(s string)    { fmt.Fprintf(w.f, "# %s\n\n", s) }
func (w *mdWriter) h2(s string)    { fmt.Fprintf(w.f, "## %s\n\n", s) }
func (w *mdWriter) h3(s string)    { fmt.Fprintf(w.f, "### %s\n\n", s) }
func (w *mdWriter) h4(s string)    { fmt.Fprintf(w.f, "#### %s\n\n", s) }
func (w *mdWriter) italic(s string) { fmt.Fprintf(w.f, "_%s_\n", s) }
func (w *mdWriter) kv(k, v string) { fmt.Fprintf(w.f, "**%s:** %s  \n", k, v) }

func (w *mdWriter) tableHeader(cols ...string) {
	w.write("| " + strings.Join(cols, " | ") + " |\n")
	seps := make([]string, len(cols))
	for i := range seps {
		seps[i] = "---"
	}
	w.write("| " + strings.Join(seps, " | ") + " |\n")
}

func (w *mdWriter) tableRow(cols ...string) {
	escaped := make([]string, len(cols))
	for i, c := range cols {
		escaped[i] = strings.ReplaceAll(c, "|", "\\|")
		escaped[i] = strings.ReplaceAll(escaped[i], "\n", " ")
	}
	w.write("| " + strings.Join(escaped, " | ") + " |\n")
}
