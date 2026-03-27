// gentoken is a helper CLI for generating HS256 JWT tokens to test the
// SecOps report server locally.
//
// Usage:
//
//	go run ./cmd/gentoken/ -secret <secret> -role <role> [-tenant <id>] [-sub <subject>]
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	secret := flag.String("secret", "", "JWT signing secret (or set SECOPS_JWT_SECRET env var)")
	role := flag.String("role", "secops-admin", "RBAC role: secops-admin|tenant-admin|compliance-auditor|engineer-readonly")
	tenantID := flag.String("tenant", "", "tenant_id claim (required for tenant-admin)")
	sub := flag.String("sub", "test-user", "subject (user identifier)")
	ttl := flag.Duration("ttl", 24*time.Hour, "token TTL (e.g. 1h, 24h, 720h)")
	flag.Parse()

	if *secret == "" {
		*secret = os.Getenv("SECOPS_JWT_SECRET")
	}
	if *secret == "" {
		fmt.Fprintln(os.Stderr, "error: -secret flag or SECOPS_JWT_SECRET env var is required")
		os.Exit(1)
	}

	if *role == "tenant-admin" && *tenantID == "" {
		fmt.Fprintln(os.Stderr, "error: -tenant is required when role is tenant-admin")
		os.Exit(1)
	}

	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	claims := map[string]any{
		"sub":  *sub,
		"role": *role,
		"exp":  time.Now().Add(*ttl).Unix(),
	}
	if *tenantID != "" {
		claims["tenant_id"] = *tenantID
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	mac := hmac.New(sha256.New, []byte(*secret))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	token := signingInput + "." + sig
	fmt.Println(token)
}
