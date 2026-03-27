package sanitizer

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/wati/secops-agent/pkg/models"
)

// piiRedactor handles IP addresses, email addresses, database names,
// API tokens, and tenant IDs.
type piiRedactor struct {
	tenantMapper *tenantMapper
}

func newPIIRedactor() *piiRedactor {
	return &piiRedactor{tenantMapper: newTenantMapper()}
}

// --- Compiled regexes (package-level, compiled once) ---

var (
	rePublicIP = regexp.MustCompile(
		`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`,
	)
	reEmail = regexp.MustCompile(
		`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
	)
	// Bearer / API key patterns: long alphanumeric strings that look like tokens.
	reToken = regexp.MustCompile(
		`(?i)(bearer\s+)[A-Za-z0-9\-_\.]{20,}`,
	)
	// Host-based server identifiers leak internal topology.
	reServerHost = regexp.MustCompile(
		`live-server-\d+\.wati\.io`,
	)
	reGenericURLHost = regexp.MustCompile(`(?i)(https?://)([^/\s]+)`)
)

// RedactIP returns a placeholder appropriate for the IP address type.
// Internal RFC-1918 addresses are kept as INTERNAL_IP to preserve context
// (e.g. distinguishing known SRE nodes from unknown sources inside the cluster).
func (r *piiRedactor) RedactIP(ip string) string {
	if ip == "" {
		return ""
	}
	if isInternalIP(ip) {
		return "INTERNAL_IP"
	}
	return "REDACTED_IP"
}

// RedactEmail replaces email addresses with a stable placeholder.
func (r *piiRedactor) RedactEmail(email string) string {
	if email == "" {
		return ""
	}
	return "REDACTED_EMAIL"
}

// RedactDatabase strips region and environment information from db names.
func (r *piiRedactor) RedactDatabase(dbName string) string {
	if dbName == "" {
		return ""
	}
	return "REDACTED_DB"
}

// RedactURL removes the host portion of a URL (which can contain tenant
// routing information) and replaces it with REDACTED_HOST. The path is kept
// because it is needed for attack-pattern analysis.
func (r *piiRedactor) RedactURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	if parsed, err := url.Parse(rawURL); err == nil {
		if parsed.Host != "" {
			parsed.Host = "REDACTED_HOST"
		}
		if parsed.RawQuery != "" {
			q := parsed.Query()
			for k := range q {
				q.Set(k, "REDACTED")
			}
			parsed.RawQuery = q.Encode()
		}
		return parsed.String()
	}

	// Replace known server host patterns first.
	cleaned := reServerHost.ReplaceAllString(rawURL, "REDACTED_HOST")
	cleaned = reGenericURLHost.ReplaceAllString(cleaned, "${1}REDACTED_HOST")
	// Replace any remaining public IPs embedded in URLs.
	cleaned = rePublicIP.ReplaceAllStringFunc(cleaned, func(ip string) string {
		if isInternalIP(ip) {
			return "INTERNAL_IP"
		}
		return "REDACTED_IP"
	})
	if i := strings.Index(cleaned, "?"); i != -1 {
		cleaned = cleaned[:i] + "?REDACTED_QUERY"
	}
	return cleaned
}

// RedactMessage redacts emails and tokens inside free-text message fields.
func (r *piiRedactor) RedactMessage(msg string) string {
	msg = reEmail.ReplaceAllString(msg, "REDACTED_EMAIL")
	msg = reToken.ReplaceAllString(msg, "${1}REDACTED_TOKEN")
	msg = rePublicIP.ReplaceAllStringFunc(msg, func(ip string) string {
		if isInternalIP(ip) {
			return "INTERNAL_IP"
		}
		return "REDACTED_IP"
	})
	return msg
}

// MapTenant converts a raw tenant_id to a stable, opaque placeholder.
// The same tenant_id always maps to the same TENANT_ID_N within a single
// pipeline run. Mappings are in-memory only and never persisted.
func (r *piiRedactor) MapTenant(scope models.LogScope, tenantID string) string {
	return r.tenantMapper.Map(scope, tenantID)
}

// isInternalIP reports whether ip is in RFC-1918 space (10.x, 172.16-31.x, 192.168.x).
func isInternalIP(ip string) bool {
	return strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		isRFC1918_172(ip)
}

func isRFC1918_172(ip string) bool {
	var a, b int
	_, err := fmt.Sscanf(ip, "%d.%d.", &a, &b)
	return err == nil && a == 172 && b >= 16 && b <= 31
}

// tenantMapper maintains a session-scoped mapping from real tenant IDs to
// opaque TENANT_ID_N placeholders. Thread-safe.
type tenantMapper struct {
	mu      sync.Mutex
	mapping map[string]string
	counter int
}

func newTenantMapper() *tenantMapper {
	return &tenantMapper{mapping: make(map[string]string)}
}

func (tm *tenantMapper) Map(scope models.LogScope, tenantID string) string {
	if scope == models.ScopePlatform {
		return "PLATFORM"
	}
	if tenantID == "" {
		return "TENANT_ID_MISSING"
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if key, ok := tm.mapping[tenantID]; ok {
		return key
	}
	tm.counter++
	key := fmt.Sprintf("TENANT_ID_%d", tm.counter)
	tm.mapping[tenantID] = key
	return key
}
