package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds all runtime configuration for the SecOps Agent.
// Values are read from environment variables so that secrets (API keys)
// are never embedded in source code or config files.
type Config struct {
	// LLM settings
	LLMProvider string // "anthropic" (default) — extend for "openai", "vertex"
	LLMAPIKey   string // SECOPS_LLM_API_KEY
	LLMModel    string // SECOPS_LLM_MODEL — empty uses provider default

	// Validation
	ConfidenceThreshold float64 // SECOPS_CONFIDENCE_THRESHOLD, default 0.7

	// I/O
	LogFilePath string // SECOPS_LOG_FILE — path to the input JSON log file
	OutputDir   string // SECOPS_OUTPUT_DIR, default "./output"
	IncludeInfo bool   // SECOPS_INCLUDE_INFO, default true

	// Server mode (DESIGN.md Q3)
	ServerPort int    // SECOPS_SERVER_PORT, default 8080
	JWTSecret  string // SECOPS_JWT_SECRET — required in serve mode

	// Remediation engine (DESIGN.md Q4)
	RemediationEnabled     bool   // SECOPS_REMEDIATION_ENABLED, default false
	RemediationDryRun      bool   // SECOPS_REMEDIATION_DRY_RUN, default true
	RemediationMinSeverity string // SECOPS_REMEDIATION_MIN_SEVERITY, default "HIGH"
	RemediationBlockIPRisk string // SECOPS_REMEDIATION_BLOCK_IP_RISK, default "low"

	// Notifier (IM integration — Feishu / Slack)
	NotifierWebhookURL         string // SECOPS_NOTIFIER_WEBHOOK_URL, default ""
	NotifierApprovalWebhookURL string // SECOPS_NOTIFIER_APPROVAL_WEBHOOK_URL, default ""
}

// Load reads configuration from environment variables.
// Returns an error if required variables are missing.
func Load() (*Config, error) {
	includeInfo, err := getEnvBoolDefault("SECOPS_INCLUDE_INFO", true)
	if err != nil {
		return nil, err
	}
	confidenceThreshold, err := getEnvFloatDefault("SECOPS_CONFIDENCE_THRESHOLD", 0.7)
	if err != nil {
		return nil, err
	}

	serverPort, err := getEnvIntDefault("SECOPS_SERVER_PORT", 8080)
	if err != nil {
		return nil, err
	}

	remEnabled, err := getEnvBoolDefault("SECOPS_REMEDIATION_ENABLED", false)
	if err != nil {
		return nil, err
	}
	remDryRun, err := getEnvBoolDefault("SECOPS_REMEDIATION_DRY_RUN", true)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		LLMProvider:         getEnvDefault("SECOPS_LLM_PROVIDER", "anthropic"),
		LLMAPIKey:           os.Getenv("SECOPS_LLM_API_KEY"),
		LLMModel:            os.Getenv("SECOPS_LLM_MODEL"),
		LogFilePath:         os.Getenv("SECOPS_LOG_FILE"),
		OutputDir:           getEnvDefault("SECOPS_OUTPUT_DIR", "./output"),
		IncludeInfo:         includeInfo,
		ConfidenceThreshold: confidenceThreshold,
		ServerPort:          serverPort,
		JWTSecret:           os.Getenv("SECOPS_JWT_SECRET"),

		RemediationEnabled:     remEnabled,
		RemediationDryRun:      remDryRun,
		RemediationMinSeverity: getEnvDefault("SECOPS_REMEDIATION_MIN_SEVERITY", "HIGH"),
		RemediationBlockIPRisk: getEnvDefault("SECOPS_REMEDIATION_BLOCK_IP_RISK", "low"),

		NotifierWebhookURL:         os.Getenv("SECOPS_NOTIFIER_WEBHOOK_URL"),
		NotifierApprovalWebhookURL: os.Getenv("SECOPS_NOTIFIER_APPROVAL_WEBHOOK_URL"),
	}

	return cfg, nil
}

// ValidateAnalyze checks that required fields for analyze mode are set.
func (c *Config) ValidateAnalyze() error {
	if c.LLMAPIKey == "" {
		return fmt.Errorf("config: SECOPS_LLM_API_KEY is required")
	}
	if c.LogFilePath == "" {
		return fmt.Errorf("config: SECOPS_LOG_FILE is required")
	}
	return nil
}

// ValidateServe checks that required fields for serve mode are set.
func (c *Config) ValidateServe() error {
	if c.JWTSecret == "" {
		return fmt.Errorf("config: SECOPS_JWT_SECRET is required in serve mode")
	}
	return nil
}

// ValidateRemediation checks that remediation config values are valid.
func (c *Config) ValidateRemediation() error {
	validSev := map[string]bool{
		"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "INFO": true,
	}
	if !validSev[strings.ToUpper(c.RemediationMinSeverity)] {
		return fmt.Errorf("config: SECOPS_REMEDIATION_MIN_SEVERITY must be CRITICAL|HIGH|MEDIUM|LOW|INFO, got %q", c.RemediationMinSeverity)
	}
	if c.RemediationBlockIPRisk != "low" && c.RemediationBlockIPRisk != "high" {
		return fmt.Errorf("config: SECOPS_REMEDIATION_BLOCK_IP_RISK must be low|high, got %q", c.RemediationBlockIPRisk)
	}
	return nil
}

func getEnvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvBoolDefault(key string, def bool) (bool, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return def, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("config: %s must be true/false, got %q", key, raw)
	}
	return v, nil
}

func getEnvFloatDefault(key string, def float64) (float64, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return def, nil
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || v < 0 || v > 1 {
		return 0, fmt.Errorf("config: %s must be 0.0–1.0, got %q", key, raw)
	}
	return v, nil
}

func getEnvIntDefault(key string, def int) (int, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return def, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 || v > 65535 {
		return 0, fmt.Errorf("config: %s must be 1–65535, got %q", key, raw)
	}
	return v, nil
}
