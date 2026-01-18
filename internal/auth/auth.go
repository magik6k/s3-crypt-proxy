// Package auth provides authentication for client requests.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Authenticator validates incoming S3 requests.
type Authenticator struct {
	accessKey string
	secretKey string
}

// NewAuthenticator creates a new authenticator.
func NewAuthenticator(accessKey, secretKey string) *Authenticator {
	return &Authenticator{
		accessKey: accessKey,
		secretKey: secretKey,
	}
}

// AuthResult contains the result of authentication.
type AuthResult struct {
	Authenticated bool
	AccessKey     string
	Error         string
}

var authHeaderRegex = regexp.MustCompile(`AWS4-HMAC-SHA256\s+Credential=([^/]+)/(\d{8})/([^/]+)/s3/aws4_request,\s*SignedHeaders=([^,]+),\s*Signature=([a-f0-9]+)`)

// Authenticate validates an incoming request.
func (a *Authenticator) Authenticate(r *http.Request) *AuthResult {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return &AuthResult{Error: "missing Authorization header"}
	}

	matches := authHeaderRegex.FindStringSubmatch(authHeader)
	if matches == nil {
		return &AuthResult{Error: "invalid Authorization header format"}
	}

	accessKey := matches[1]
	dateStr := matches[2]
	region := matches[3]
	signedHeadersStr := matches[4]
	providedSignature := matches[5]

	if accessKey != a.accessKey {
		return &AuthResult{Error: "invalid access key"}
	}

	// Get the date from the request
	amzDate := r.Header.Get("x-amz-date")
	if amzDate == "" {
		return &AuthResult{Error: "missing x-amz-date header"}
	}

	// Parse and validate the timestamp (allow 15 minute skew)
	requestTime, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		return &AuthResult{Error: "invalid x-amz-date format"}
	}

	timeDiff := time.Since(requestTime)
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}
	if timeDiff > 15*time.Minute {
		return &AuthResult{Error: "request timestamp too old or in future"}
	}

	// Calculate the expected signature
	expectedSignature := a.calculateSignature(r, dateStr, region, signedHeadersStr, amzDate)

	if !hmac.Equal([]byte(expectedSignature), []byte(providedSignature)) {
		return &AuthResult{Error: "signature mismatch"}
	}

	return &AuthResult{
		Authenticated: true,
		AccessKey:     accessKey,
	}
}

func (a *Authenticator) calculateSignature(r *http.Request, dateStr, region, signedHeadersStr, amzDate string) string {
	// Create canonical request
	canonicalURI := r.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	canonicalQuery := r.URL.RawQuery

	// Build canonical headers
	signedHeaders := strings.Split(signedHeadersStr, ";")
	sort.Strings(signedHeaders)

	var canonicalHeaders strings.Builder
	for _, key := range signedHeaders {
		canonicalHeaders.WriteString(key)
		canonicalHeaders.WriteString(":")
		if key == "host" {
			canonicalHeaders.WriteString(r.Host)
		} else {
			canonicalHeaders.WriteString(strings.TrimSpace(r.Header.Get(key)))
		}
		canonicalHeaders.WriteString("\n")
	}

	payloadHash := r.Header.Get("x-amz-content-sha256")
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
	}

	canonicalRequest := strings.Join([]string{
		r.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders.String(),
		signedHeadersStr,
		payloadHash,
	}, "\n")

	// Create string to sign
	credentialScope := dateStr + "/" + region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + credentialScope + "\n" + hashSHA256([]byte(canonicalRequest))

	// Calculate signature
	kDate := hmacSHA256([]byte("AWS4"+a.secretKey), []byte(dateStr))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte("s3"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	return signature
}

func hashSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// AdminAuthenticator validates admin API requests.
type AdminAuthenticator struct {
	token string
}

// NewAdminAuthenticator creates a new admin authenticator.
func NewAdminAuthenticator(token string) *AdminAuthenticator {
	return &AdminAuthenticator{token: token}
}

// Authenticate validates an admin request.
func (a *AdminAuthenticator) Authenticate(r *http.Request) error {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return fmt.Errorf("missing Authorization header")
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return fmt.Errorf("invalid Authorization header format")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token != a.token {
		return fmt.Errorf("invalid token")
	}

	return nil
}
