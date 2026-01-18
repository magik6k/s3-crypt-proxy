package s3client

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// hashSHA256 returns the hex-encoded SHA256 hash of data.
func hashSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// hmacSHA256 computes HMAC-SHA256.
func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// calculatePayloadHash calculates the SHA256 hash of a request body.
func calculatePayloadHash(body io.ReadSeeker) string {
	h := sha256.New()
	io.Copy(h, body)
	return hex.EncodeToString(h.Sum(nil))
}
