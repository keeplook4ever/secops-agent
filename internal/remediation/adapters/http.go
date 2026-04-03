package adapters

import (
	"context"
	"net/http"

	"secops-agent/internal/remediation"
)

// HTTPRateLimiter calls the internal rate-limit API.
//
// TODO: implement when API contract is known.
// Expected request shape (to be confirmed with platform team):
//
//	POST <baseURL>/rate-limit
//	Authorization: Bearer <token>
//	{
//	  "tenant_id": "<tenant_id>",
//	  "action": "apply",
//	  "ttl_seconds": 300
//	}
type HTTPRateLimiter struct {
	client  *http.Client
	baseURL string
	token   string
}

func NewHTTPRateLimiter(baseURL, token string) *HTTPRateLimiter {
	return &HTTPRateLimiter{client: &http.Client{}, baseURL: baseURL, token: token}
}

func (a *HTTPRateLimiter) RateLimit(_ context.Context, _ remediation.ActionSpec) error {
	panic("HTTPRateLimiter.RateLimit: not yet implemented — waiting for internal API contract")
}

// HTTPIPBlocker calls the internal firewall / WAF API.
//
// TODO: implement when API contract is known.
// Expected request shape (to be confirmed with platform team):
//
//	POST <baseURL>/block-ip
//	Authorization: Bearer <token>
//	{
//	  "ip": "<source_ip>",       ← from ActionSpec.Meta["ip"] once pipeline is enriched
//	  "tenant_id": "<tenant_id>",
//	  "ttl_seconds": 3600
//	}
type HTTPIPBlocker struct {
	client  *http.Client
	baseURL string
	token   string
}

func NewHTTPIPBlocker(baseURL, token string) *HTTPIPBlocker {
	return &HTTPIPBlocker{client: &http.Client{}, baseURL: baseURL, token: token}
}

func (a *HTTPIPBlocker) BlockIP(_ context.Context, _ remediation.ActionSpec) error {
	panic("HTTPIPBlocker.BlockIP: not yet implemented — waiting for internal API contract")
}

// HTTPAccountBanner calls the internal account management API.
//
// TODO: implement when API contract is known.
// Expected request shape (to be confirmed with platform team):
//
//	POST <baseURL>/accounts/ban
//	Authorization: Bearer <token>
//	{
//	  "tenant_id": "<tenant_id>",
//	  "user_email": "<email>",    ← from ActionSpec.Meta["email"] once pipeline is enriched
//	  "reason": "<attack_pattern>"
//	}
type HTTPAccountBanner struct {
	client  *http.Client
	baseURL string
	token   string
}

func NewHTTPAccountBanner(baseURL, token string) *HTTPAccountBanner {
	return &HTTPAccountBanner{client: &http.Client{}, baseURL: baseURL, token: token}
}

func (a *HTTPAccountBanner) BanAccount(_ context.Context, _ remediation.ActionSpec) error {
	panic("HTTPAccountBanner.BanAccount: not yet implemented — waiting for internal API contract")
}

// HTTPTenantIsolator calls the internal tenant management API.
//
// TODO: implement when API contract is known.
// Expected request shape (to be confirmed with platform team):
//
//	POST <baseURL>/tenants/isolate
//	Authorization: Bearer <token>
//	{
//	  "tenant_id": "<tenant_id>",
//	  "isolation_level": "full",  ← or "network" / "data"; confirm with platform team
//	  "reason": "<attack_pattern>"
//	}
type HTTPTenantIsolator struct {
	client  *http.Client
	baseURL string
	token   string
}

func NewHTTPTenantIsolator(baseURL, token string) *HTTPTenantIsolator {
	return &HTTPTenantIsolator{client: &http.Client{}, baseURL: baseURL, token: token}
}

func (a *HTTPTenantIsolator) IsolateTenant(_ context.Context, _ remediation.ActionSpec) error {
	panic("HTTPTenantIsolator.IsolateTenant: not yet implemented — waiting for internal API contract")
}

// HTTPNotifier sends security alerts and approval requests to an IM system (Feishu / Slack).
//
// TODO: implement when IM webhook URLs are configured.
//
// Feishu incoming webhook (approval_required=false — security alert):
//
//	POST https://open.feishu.cn/open-apis/bot/v2/hook/<token>
//	{"msg_type":"interactive","card":{"header":{"title":{"content":"🔴 SecOps Alert: <attack_pattern>","tag":"plain_text"}},"elements":[{"tag":"div","text":{"content":"Tenant: <tenant_id>\nSeverity: <severity>\nRequest ID: <request_id>","tag":"lark_md"}}]}}
//
// Feishu incoming webhook (approval_required=true — approval request):
//
//	Same structure but add "actions" elements with approve/reject buttons.
//	Button callback URL: POST /remediation/approve?key=<dedupe_key>
//
// Slack incoming webhook (approval_required=true):
//
//	POST https://hooks.slack.com/services/<token>
//	{"blocks":[{"type":"section","text":{"type":"mrkdwn","text":"*Action Required:* <action_type>\nTenant: <tenant_id>"}},{"type":"actions","elements":[{"type":"button","text":{"type":"plain_text","text":"Approve"},"url":"<approve_url>"},{"type":"button","text":{"type":"plain_text","text":"Reject"},"url":"<reject_url>"}]}]}
//
// Configure via:
//
//	SECOPS_NOTIFIER_WEBHOOK_URL          — general alert webhook
//	SECOPS_NOTIFIER_APPROVAL_WEBHOOK_URL — approval request webhook (falls back to above)
type HTTPNotifier struct {
	client             *http.Client
	webhookURL         string
	approvalWebhookURL string // falls back to webhookURL if empty
}

func NewHTTPNotifier(webhookURL, approvalWebhookURL string) *HTTPNotifier {
	url := approvalWebhookURL
	if url == "" {
		url = webhookURL
	}
	return &HTTPNotifier{
		client:             &http.Client{},
		webhookURL:         webhookURL,
		approvalWebhookURL: url,
	}
}

func (a *HTTPNotifier) Notify(_ context.Context, _ remediation.ActionSpec) error {
	panic("HTTPNotifier.Notify: not yet implemented — set SECOPS_NOTIFIER_WEBHOOK_URL and implement message templates")
}
