package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Role defines the RBAC roles from DESIGN.md Question 3.
type Role string

const (
	RoleSecOpsAdmin       Role = "secops-admin"
	RoleTenantAdmin       Role = "tenant-admin"
	RoleComplianceAuditor Role = "compliance-auditor"
	RoleEngineerReadonly   Role = "engineer-readonly"
)

// Claims represents the JWT payload we expect.
type Claims struct {
	Sub      string `json:"sub"`       // subject (user ID or service account)
	Role     Role   `json:"role"`      // RBAC role
	TenantID string `json:"tenant_id"` // non-empty only for tenant-admin
	Exp      int64  `json:"exp"`       // expiration (unix timestamp)
}

// authMiddleware extracts and validates the JWT from the Authorization header,
// then stores the Claims in the request context for downstream handlers.
func authMiddleware(secret []byte, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeError(w, http.StatusUnauthorized, "missing Authorization header")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			writeError(w, http.StatusUnauthorized, "invalid Authorization format, expected: Bearer <token>")
			return
		}

		claims, err := parseJWT(parts[1], secret)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}

		// Validate role is known.
		switch claims.Role {
		case RoleSecOpsAdmin, RoleTenantAdmin, RoleComplianceAuditor, RoleEngineerReadonly:
			// valid
		default:
			writeError(w, http.StatusForbidden, fmt.Sprintf("unknown role %q", claims.Role))
			return
		}

		// tenant-admin must have a tenant_id claim.
		if claims.Role == RoleTenantAdmin && claims.TenantID == "" {
			writeError(w, http.StatusForbidden, "tenant-admin role requires tenant_id claim")
			return
		}

		ctx := withClaims(r.Context(), claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// parseJWT validates an HMAC-SHA256 signed JWT and returns its claims.
// This is a minimal implementation using only the standard library;
// it supports the HS256 algorithm required for this internal service.
func parseJWT(tokenStr string, secret []byte) (*Claims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWT: expected 3 parts, got %d", len(parts))
	}

	// Verify signature.
	signingInput := parts[0] + "." + parts[1]
	signature, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jwt: decode signature: %w", err)
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	expected := mac.Sum(nil)
	if !hmac.Equal(signature, expected) {
		return nil, fmt.Errorf("jwt: invalid signature")
	}

	// Decode header to check alg.
	headerJSON, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwt: decode header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("jwt: parse header: %w", err)
	}
	if header.Alg != "HS256" {
		return nil, fmt.Errorf("jwt: unsupported algorithm %q", header.Alg)
	}

	// Decode claims.
	payloadJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt: decode payload: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("jwt: parse claims: %w", err)
	}

	return &claims, nil
}

// base64URLDecode decodes a base64url string (no padding).
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed.
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
