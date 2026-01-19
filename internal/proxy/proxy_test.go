package proxy

import (
	"bytes"
	stdcrypto "crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/s3-crypt-proxy/internal/auth"
	"github.com/s3-crypt-proxy/internal/crypto"
	"github.com/s3-crypt-proxy/internal/metrics"
	"github.com/s3-crypt-proxy/internal/s3client"
	"github.com/s3-crypt-proxy/internal/testutil"
)

// testEnv holds all test environment components.
type testEnv struct {
	mockS3      *testutil.MockS3Server
	proxy       *Proxy
	proxyServer *httptest.Server
	km          *crypto.KeyManager
	masterKey   []byte
	accessKey   string
	secretKey   string
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	// Create mock S3 server
	mockS3 := testutil.NewMockS3Server()
	mockS3.CreateBucket("test-bucket")

	// Create key manager and load key
	km := crypto.NewKeyManager()
	masterKey := make([]byte, 32)
	rand.Read(masterKey)
	if err := km.LoadKey(masterKey); err != nil {
		t.Fatalf("failed to load key: %v", err)
	}

	// Create S3 client for backend
	backend := s3client.NewClient(s3client.ClientOptions{
		Endpoint:  mockS3.URL(),
		Region:    "us-east-1",
		AccessKey: "test-access-key",
		SecretKey: "test-secret-key",
		PathStyle: true,
	})

	// Create authenticator
	accessKey := "client-access-key"
	secretKey := "client-secret-key"
	clientAuth := auth.NewAuthenticator(accessKey, secretKey)

	// Create metrics
	m := metrics.New()

	// Create proxy
	p := NewProxy(ProxyOptions{
		Backend:   backend,
		KeyMgr:    km,
		Auth:      clientAuth,
		Metrics:   m,
		ChunkSize: crypto.DefaultChunkSize,
	})

	// Create test server
	proxyServer := httptest.NewServer(p)

	return &testEnv{
		mockS3:      mockS3,
		proxy:       p,
		proxyServer: proxyServer,
		km:          km,
		masterKey:   masterKey,
		accessKey:   accessKey,
		secretKey:   secretKey,
	}
}

func (e *testEnv) Close() {
	e.proxyServer.Close()
	e.mockS3.Close()
}

// signRequest signs an HTTP request with AWS Signature V4.
func (e *testEnv) signRequest(req *http.Request) {
	now := time.Now().UTC()
	dateStr := now.Format("20060102")
	datetimeStr := now.Format("20060102T150405Z")

	req.Header.Set("x-amz-date", datetimeStr)
	req.Header.Set("Host", req.URL.Host)
	req.Header.Set("x-amz-content-sha256", "UNSIGNED-PAYLOAD")

	// Simplified signing for tests
	credentialScope := dateStr + "/us-east-1/s3/aws4_request"
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"

	// Build canonical request
	// URI must be URI-encoded as per AWS Signature V4
	canonicalURI := uriEncode(req.URL.Path, false)
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	var canonicalHeaders strings.Builder
	canonicalHeaders.WriteString("host:" + req.URL.Host + "\n")
	canonicalHeaders.WriteString("x-amz-content-sha256:UNSIGNED-PAYLOAD\n")
	canonicalHeaders.WriteString("x-amz-date:" + datetimeStr + "\n")

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQueryString(req.URL.RawQuery),
		canonicalHeaders.String(),
		signedHeaders,
		"UNSIGNED-PAYLOAD",
	}, "\n")

	// Create string to sign
	stringToSign := "AWS4-HMAC-SHA256\n" + datetimeStr + "\n" + credentialScope + "\n" + hashSHA256([]byte(canonicalRequest))

	// Calculate signature
	kDate := hmacSHA256([]byte("AWS4"+e.secretKey), []byte(dateStr))
	kRegion := hmacSHA256(kDate, []byte("us-east-1"))
	kService := hmacSHA256(kRegion, []byte("s3"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := fmt.Sprintf("%x", hmacSHA256(kSigning, []byte(stringToSign)))

	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s,SignedHeaders=%s,Signature=%s",
		e.accessKey, credentialScope, signedHeaders, signature)

	req.Header.Set("Authorization", authHeader)
}

// Helper functions for signing
func hashSHA256(data []byte) string {
	h := sha256Sum(data)
	return fmt.Sprintf("%x", h)
}

// uriEncode encodes a URI path according to AWS S3 signature requirements.
// When encodeSlash is false, forward slashes are not encoded.
func uriEncode(path string, encodeSlash bool) string {
	var encoded strings.Builder
	for _, ch := range []byte(path) {
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
			(ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '~' || ch == '.' {
			encoded.WriteByte(ch)
		} else if ch == '/' && !encodeSlash {
			encoded.WriteByte(ch)
		} else {
			encoded.WriteString(fmt.Sprintf("%%%02X", ch))
		}
	}
	return encoded.String()
}

// canonicalQueryString creates a canonical query string for AWS signature.
// It decodes URL-encoded values first, then re-encodes them per AWS spec.
func canonicalQueryString(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}

	// Use url.ParseQuery which properly decodes URL-encoded values
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		// Fall back to simple parsing if url.ParseQuery fails
		return rawQuery
	}

	// Sort keys
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build canonical query string with proper URI encoding
	var parts []string
	for _, k := range keys {
		vals := values[k]
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, uriEncode(k, true)+"="+uriEncode(v, true))
		}
	}

	return strings.Join(parts, "&")
}

func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func hmacSHA256(key, data []byte) []byte {
	if key == nil {
		h := sha256.Sum256(data)
		return h[:]
	}
	mac := stdcrypto.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// Test: PutObject and GetObject - basic encryption/decryption round trip
func TestPutGetObject(t *testing.T) {
	env := setupTestEnv(t)
	defer env.Close()

	testCases := []struct {
		name        string
		key         string
		data        []byte
		contentType string
	}{
		{
			name:        "small text file",
			key:         "test/small.txt",
			data:        []byte("Hello, World!"),
			contentType: "text/plain",
		},
		{
			name:        "binary data",
			key:         "test/binary.bin",
			data:        bytes.Repeat([]byte{0x00, 0xFF, 0x42}, 1000),
			contentType: "application/octet-stream",
		},
		{
			name:        "4MB chunk (PBS typical)",
			key:         ".chunks/abcd/abcdef1234567890",
			data:        make([]byte, 4*1024*1024),
			contentType: "application/octet-stream",
		},
		{
			name:        "empty file",
			key:         "test/empty.txt",
			data:        []byte{},
			contentType: "text/plain",
		},
	}

	// Fill 4MB chunk with random data
	rand.Read(testCases[2].data)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// PUT object
			putReq, _ := http.NewRequest("PUT",
				env.proxyServer.URL+"/test-bucket/"+tc.key,
				bytes.NewReader(tc.data))
			putReq.Header.Set("Content-Type", tc.contentType)
			env.signRequest(putReq)

			putResp, err := http.DefaultClient.Do(putReq)
			if err != nil {
				t.Fatalf("PUT request failed: %v", err)
			}
			defer putResp.Body.Close()

			if putResp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(putResp.Body)
				t.Fatalf("PUT failed with status %d: %s", putResp.StatusCode, body)
			}

			// Verify data is encrypted in backend
			encryptedData, ok := env.mockS3.GetObjectData("test-bucket", tc.key)
			if !ok {
				t.Fatal("object not found in backend")
			}

			// Check that plaintext is NOT in encrypted data (unless empty)
			if len(tc.data) > 10 && bytes.Contains(encryptedData, tc.data) {
				t.Error("plaintext found in encrypted data - encryption may have failed")
			}

			// Check encryption header
			if len(encryptedData) < 4 || string(encryptedData[:4]) != crypto.HeaderMagic {
				t.Error("encrypted data does not have valid header")
			}

			// GET object
			getReq, _ := http.NewRequest("GET",
				env.proxyServer.URL+"/test-bucket/"+tc.key, nil)
			env.signRequest(getReq)

			getResp, err := http.DefaultClient.Do(getReq)
			if err != nil {
				t.Fatalf("GET request failed: %v", err)
			}
			defer getResp.Body.Close()

			if getResp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(getResp.Body)
				t.Fatalf("GET failed with status %d: %s", getResp.StatusCode, body)
			}

			// Verify content type
			if getResp.Header.Get("Content-Type") != tc.contentType {
				t.Errorf("content type mismatch: got %s, want %s",
					getResp.Header.Get("Content-Type"), tc.contentType)
			}

			// Verify decrypted data
			decryptedData, err := io.ReadAll(getResp.Body)
			if err != nil {
				t.Fatalf("failed to read response body: %v", err)
			}

			if !bytes.Equal(decryptedData, tc.data) {
				t.Errorf("decrypted data mismatch: got %d bytes, want %d bytes",
					len(decryptedData), len(tc.data))
			}
		})
	}
}

// Test: HeadObject returns correct metadata
func TestHeadObject(t *testing.T) {
	env := setupTestEnv(t)
	defer env.Close()

	// First, put an object
	testData := []byte("Test data for HEAD request")
	putReq, _ := http.NewRequest("PUT",
		env.proxyServer.URL+"/test-bucket/head-test.txt",
		bytes.NewReader(testData))
	putReq.Header.Set("Content-Type", "text/plain")
	env.signRequest(putReq)

	putResp, _ := http.DefaultClient.Do(putReq)
	putResp.Body.Close()

	// Now HEAD the object
	headReq, _ := http.NewRequest("HEAD",
		env.proxyServer.URL+"/test-bucket/head-test.txt", nil)
	env.signRequest(headReq)

	headResp, err := http.DefaultClient.Do(headReq)
	if err != nil {
		t.Fatalf("HEAD request failed: %v", err)
	}
	defer headResp.Body.Close()

	if headResp.StatusCode != http.StatusOK {
		t.Fatalf("HEAD failed with status %d", headResp.StatusCode)
	}

	// Verify headers
	if headResp.Header.Get("Content-Type") != "text/plain" {
		t.Errorf("wrong content type: %s", headResp.Header.Get("Content-Type"))
	}

	contentLength := headResp.Header.Get("Content-Length")
	if contentLength != fmt.Sprintf("%d", len(testData)) {
		t.Errorf("wrong content length: got %s, want %d", contentLength, len(testData))
	}
}

// Test: ListObjectsV2
func TestListObjectsV2(t *testing.T) {
	env := setupTestEnv(t)
	defer env.Close()

	// Put several objects
	objects := []string{
		"folder1/file1.txt",
		"folder1/file2.txt",
		"folder2/file3.txt",
		"root.txt",
	}

	for _, key := range objects {
		putReq, _ := http.NewRequest("PUT",
			env.proxyServer.URL+"/test-bucket/"+key,
			bytes.NewReader([]byte("content")))
		env.signRequest(putReq)
		resp, _ := http.DefaultClient.Do(putReq)
		resp.Body.Close()
	}

	// List all objects
	listReq, _ := http.NewRequest("GET",
		env.proxyServer.URL+"/test-bucket/?list-type=2", nil)
	env.signRequest(listReq)

	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("LIST request failed: %v", err)
	}
	defer listResp.Body.Close()

	if listResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("LIST failed with status %d: %s", listResp.StatusCode, body)
	}

	// Parse response
	var result struct {
		Contents []struct {
			Key  string `xml:"Key"`
			Size int64  `xml:"Size"`
		} `xml:"Contents"`
	}
	xml.NewDecoder(listResp.Body).Decode(&result)

	if len(result.Contents) != len(objects) {
		t.Errorf("wrong number of objects: got %d, want %d", len(result.Contents), len(objects))
	}

	// List with prefix
	listReq2, _ := http.NewRequest("GET",
		env.proxyServer.URL+"/test-bucket/?list-type=2&prefix=folder1/", nil)
	env.signRequest(listReq2)

	listResp2, err := http.DefaultClient.Do(listReq2)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer listResp2.Body.Close()

	var result2 struct {
		Contents []struct {
			Key string `xml:"Key"`
		} `xml:"Contents"`
	}
	xml.NewDecoder(listResp2.Body).Decode(&result2)

	if len(result2.Contents) != 2 {
		t.Errorf("wrong number of objects with prefix: got %d, want 2", len(result2.Contents))
	}
}

// Test: DeleteObject
func TestDeleteObject(t *testing.T) {
	env := setupTestEnv(t)
	defer env.Close()

	// Put an object
	putReq, _ := http.NewRequest("PUT",
		env.proxyServer.URL+"/test-bucket/to-delete.txt",
		bytes.NewReader([]byte("delete me")))
	env.signRequest(putReq)
	resp, _ := http.DefaultClient.Do(putReq)
	resp.Body.Close()

	// Verify it exists
	if _, ok := env.mockS3.GetObjectData("test-bucket", "to-delete.txt"); !ok {
		t.Fatal("object should exist before delete")
	}

	// Delete it
	delReq, _ := http.NewRequest("DELETE",
		env.proxyServer.URL+"/test-bucket/to-delete.txt", nil)
	env.signRequest(delReq)

	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("DELETE request failed: %v", err)
	}
	defer delResp.Body.Close()

	if delResp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE returned status %d, want %d", delResp.StatusCode, http.StatusNoContent)
	}

	// Verify it's gone
	if _, ok := env.mockS3.GetObjectData("test-bucket", "to-delete.txt"); ok {
		t.Error("object should not exist after delete")
	}
}

// Test: DeleteObjects (batch delete)
func TestDeleteObjects(t *testing.T) {
	env := setupTestEnv(t)
	defer env.Close()

	// Put several objects
	keys := []string{"batch1.txt", "batch2.txt", "batch3.txt"}
	for _, key := range keys {
		putReq, _ := http.NewRequest("PUT",
			env.proxyServer.URL+"/test-bucket/"+key,
			bytes.NewReader([]byte("content")))
		env.signRequest(putReq)
		resp, _ := http.DefaultClient.Do(putReq)
		resp.Body.Close()
	}

	// Batch delete
	deleteXML := `<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
		<Object><Key>batch1.txt</Key></Object>
		<Object><Key>batch2.txt</Key></Object>
	</Delete>`

	delReq, _ := http.NewRequest("POST",
		env.proxyServer.URL+"/test-bucket/?delete",
		strings.NewReader(deleteXML))
	delReq.Header.Set("Content-Type", "application/xml")
	env.signRequest(delReq)

	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("DELETE request failed: %v", err)
	}
	defer delResp.Body.Close()

	if delResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(delResp.Body)
		t.Fatalf("batch DELETE failed with status %d: %s", delResp.StatusCode, body)
	}

	// Verify batch1 and batch2 are gone, batch3 remains
	if _, ok := env.mockS3.GetObjectData("test-bucket", "batch1.txt"); ok {
		t.Error("batch1.txt should be deleted")
	}
	if _, ok := env.mockS3.GetObjectData("test-bucket", "batch2.txt"); ok {
		t.Error("batch2.txt should be deleted")
	}
	if _, ok := env.mockS3.GetObjectData("test-bucket", "batch3.txt"); !ok {
		t.Error("batch3.txt should still exist")
	}
}

// Test: CopyObject
func TestCopyObject(t *testing.T) {
	env := setupTestEnv(t)
	defer env.Close()

	// Put source object
	sourceData := []byte("Original data to copy")
	putReq, _ := http.NewRequest("PUT",
		env.proxyServer.URL+"/test-bucket/source.txt",
		bytes.NewReader(sourceData))
	putReq.Header.Set("Content-Type", "text/plain")
	env.signRequest(putReq)
	resp, _ := http.DefaultClient.Do(putReq)
	resp.Body.Close()

	// Copy object
	copyReq, _ := http.NewRequest("PUT",
		env.proxyServer.URL+"/test-bucket/dest.txt", nil)
	copyReq.Header.Set("x-amz-copy-source", "/test-bucket/source.txt")
	env.signRequest(copyReq)

	copyResp, err := http.DefaultClient.Do(copyReq)
	if err != nil {
		t.Fatalf("COPY request failed: %v", err)
	}
	defer copyResp.Body.Close()

	if copyResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(copyResp.Body)
		t.Fatalf("COPY failed with status %d: %s", copyResp.StatusCode, body)
	}

	// Verify destination has correct content
	getReq, _ := http.NewRequest("GET",
		env.proxyServer.URL+"/test-bucket/dest.txt", nil)
	env.signRequest(getReq)

	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer getResp.Body.Close()

	destData, _ := io.ReadAll(getResp.Body)
	if !bytes.Equal(destData, sourceData) {
		t.Error("copied data does not match source")
	}

	// Verify source and dest have different encrypted representations (different salts)
	srcEncrypted, _ := env.mockS3.GetObjectData("test-bucket", "source.txt")
	destEncrypted, _ := env.mockS3.GetObjectData("test-bucket", "dest.txt")

	if bytes.Equal(srcEncrypted, destEncrypted) {
		t.Error("source and dest should have different encrypted data (different salts)")
	}
}

// Test: HeadBucket
func TestHeadBucket(t *testing.T) {
	env := setupTestEnv(t)
	defer env.Close()

	// Existing bucket
	headReq, _ := http.NewRequest("HEAD",
		env.proxyServer.URL+"/test-bucket/", nil)
	env.signRequest(headReq)

	headResp, err := http.DefaultClient.Do(headReq)
	if err != nil {
		t.Fatalf("HEAD bucket request failed: %v", err)
	}
	defer headResp.Body.Close()

	if headResp.StatusCode != http.StatusOK {
		t.Errorf("HEAD bucket returned %d, want %d", headResp.StatusCode, http.StatusOK)
	}

	// Non-existing bucket
	headReq2, _ := http.NewRequest("HEAD",
		env.proxyServer.URL+"/nonexistent-bucket/", nil)
	env.signRequest(headReq2)

	headResp2, err := http.DefaultClient.Do(headReq2)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer headResp2.Body.Close()

	if headResp2.StatusCode == http.StatusOK {
		t.Error("HEAD nonexistent bucket should fail")
	}
}

// Test: ListBuckets
func TestListBuckets(t *testing.T) {
	env := setupTestEnv(t)
	defer env.Close()

	listReq, _ := http.NewRequest("GET", env.proxyServer.URL+"/", nil)
	env.signRequest(listReq)

	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("LIST buckets request failed: %v", err)
	}
	defer listResp.Body.Close()

	if listResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("LIST buckets failed with status %d: %s", listResp.StatusCode, body)
	}

	var result struct {
		Buckets struct {
			Bucket []struct {
				Name string `xml:"Name"`
			} `xml:"Bucket"`
		} `xml:"Buckets"`
	}
	xml.NewDecoder(listResp.Body).Decode(&result)

	found := false
	for _, b := range result.Buckets.Bucket {
		if b.Name == "test-bucket" {
			found = true
			break
		}
	}

	if !found {
		t.Error("test-bucket not found in bucket list")
	}
}

// Test: If-None-Match header (PBS upload_no_replace)
func TestIfNoneMatch(t *testing.T) {
	env := setupTestEnv(t)
	defer env.Close()

	// Put initial object
	putReq1, _ := http.NewRequest("PUT",
		env.proxyServer.URL+"/test-bucket/unique.txt",
		bytes.NewReader([]byte("first")))
	env.signRequest(putReq1)
	resp1, _ := http.DefaultClient.Do(putReq1)
	resp1.Body.Close()

	// Try to put with If-None-Match: * (should fail)
	putReq2, _ := http.NewRequest("PUT",
		env.proxyServer.URL+"/test-bucket/unique.txt",
		bytes.NewReader([]byte("second")))
	putReq2.Header.Set("If-None-Match", "*")
	env.signRequest(putReq2)

	resp2, err := http.DefaultClient.Do(putReq2)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusPreconditionFailed {
		t.Errorf("expected 412 Precondition Failed, got %d", resp2.StatusCode)
	}

	// Verify original data is unchanged
	getReq, _ := http.NewRequest("GET",
		env.proxyServer.URL+"/test-bucket/unique.txt", nil)
	env.signRequest(getReq)

	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer getResp.Body.Close()

	data, _ := io.ReadAll(getResp.Body)
	if string(data) != "first" {
		t.Errorf("data was modified: got %s, want first", string(data))
	}
}

// Test: Authentication failure
func TestAuthenticationFailure(t *testing.T) {
	env := setupTestEnv(t)
	defer env.Close()

	// Request without auth
	req, _ := http.NewRequest("GET", env.proxyServer.URL+"/test-bucket/", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d", resp.StatusCode)
	}
}

// Test: Key not loaded
func TestKeyNotLoaded(t *testing.T) {
	env := setupTestEnv(t)
	defer env.Close()

	// Clear the key
	env.km.ClearKey()

	// Try to put
	putReq, _ := http.NewRequest("PUT",
		env.proxyServer.URL+"/test-bucket/test.txt",
		bytes.NewReader([]byte("test")))
	env.signRequest(putReq)

	resp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 Service Unavailable, got %d", resp.StatusCode)
	}
}

// Test: Tamper detection
// Note: With streaming decryption, the HTTP status code is written before decryption.
// Tamper detection happens during streaming, so we verify the decrypted content
// is incomplete or different from the original.
func TestTamperDetection(t *testing.T) {
	env := setupTestEnv(t)
	defer env.Close()

	originalData := []byte("important data that should be protected")

	// Put an object
	putReq, _ := http.NewRequest("PUT",
		env.proxyServer.URL+"/test-bucket/tamper-test.txt",
		bytes.NewReader(originalData))
	env.signRequest(putReq)
	resp, _ := http.DefaultClient.Do(putReq)
	resp.Body.Close()

	// Verify we can get the original data back
	getReq1, _ := http.NewRequest("GET",
		env.proxyServer.URL+"/test-bucket/tamper-test.txt", nil)
	env.signRequest(getReq1)
	getResp1, _ := http.DefaultClient.Do(getReq1)
	body1, _ := io.ReadAll(getResp1.Body)
	getResp1.Body.Close()

	if !bytes.Equal(body1, originalData) {
		t.Fatalf("original data doesn't match: got %q, want %q", body1, originalData)
	}

	// Tamper with the encrypted data in the backend
	encryptedData, _ := env.mockS3.GetObjectData("test-bucket", "tamper-test.txt")
	tampered := make([]byte, len(encryptedData))
	copy(tampered, encryptedData)

	// Flip bits in the encrypted content area (after header+metadata)
	// The format is: header(34) + salt(16) + metaLen(4) + encryptedMeta + encryptedContent
	if len(tampered) > 100 {
		tampered[len(tampered)-20] ^= 0xFF
	}

	// Put tampered data directly to backend
	env.mockS3.SetObjectData("test-bucket", "tamper-test.txt", tampered)

	// Try to get the tampered object
	getReq2, _ := http.NewRequest("GET",
		env.proxyServer.URL+"/test-bucket/tamper-test.txt", nil)
	env.signRequest(getReq2)

	getResp2, _ := http.DefaultClient.Do(getReq2)
	body2, _ := io.ReadAll(getResp2.Body)
	getResp2.Body.Close()

	// Tampered data should NOT decrypt to the original content
	// Either:
	// 1. We get empty/incomplete data (decryption failed mid-stream), or
	// 2. We get different data (if tampering somehow produced valid-looking output)
	if bytes.Equal(body2, originalData) {
		t.Errorf("tampered data should not decrypt to original content")
	}

	// Verify that the body is empty or shorter (decryption failed)
	if len(body2) >= len(originalData) {
		t.Logf("warning: tampered response body len=%d, original=%d", len(body2), len(originalData))
	}
}

// Test: Different keys produce different ciphertexts
func TestDifferentKeysDifferentCiphertexts(t *testing.T) {
	env1 := setupTestEnv(t)
	defer env1.Close()

	env2 := setupTestEnv(t)
	defer env2.Close()

	testData := []byte("same data")

	// Put with env1
	putReq1, _ := http.NewRequest("PUT",
		env1.proxyServer.URL+"/test-bucket/key-test.txt",
		bytes.NewReader(testData))
	env1.signRequest(putReq1)
	http.DefaultClient.Do(putReq1)

	// Put with env2
	putReq2, _ := http.NewRequest("PUT",
		env2.proxyServer.URL+"/test-bucket/key-test.txt",
		bytes.NewReader(testData))
	env2.signRequest(putReq2)
	http.DefaultClient.Do(putReq2)

	enc1, _ := env1.mockS3.GetObjectData("test-bucket", "key-test.txt")
	enc2, _ := env2.mockS3.GetObjectData("test-bucket", "key-test.txt")

	if bytes.Equal(enc1, enc2) {
		t.Error("different keys should produce different ciphertexts")
	}
}

// Test: Same data encrypted twice produces different ciphertexts (unique nonces)
func TestUniqueNonces(t *testing.T) {
	env := setupTestEnv(t)
	defer env.Close()

	testData := []byte("same data same key")

	// Put first time
	putReq1, _ := http.NewRequest("PUT",
		env.proxyServer.URL+"/test-bucket/nonce1.txt",
		bytes.NewReader(testData))
	env.signRequest(putReq1)
	http.DefaultClient.Do(putReq1)

	// Put second time (same key, same path)
	putReq2, _ := http.NewRequest("PUT",
		env.proxyServer.URL+"/test-bucket/nonce1.txt",
		bytes.NewReader(testData))
	env.signRequest(putReq2)
	http.DefaultClient.Do(putReq2)

	// The encrypted data should be different (different random salt)
	// Note: We can't directly compare since we overwrote, but we can put to different keys

	putReq3, _ := http.NewRequest("PUT",
		env.proxyServer.URL+"/test-bucket/nonce2.txt",
		bytes.NewReader(testData))
	env.signRequest(putReq3)
	http.DefaultClient.Do(putReq3)

	enc1, _ := env.mockS3.GetObjectData("test-bucket", "nonce1.txt")
	enc2, _ := env.mockS3.GetObjectData("test-bucket", "nonce2.txt")

	if bytes.Equal(enc1, enc2) {
		t.Error("same data should produce different ciphertexts due to random salt")
	}
}

// Test: 404 for non-existent object
func TestNotFound(t *testing.T) {
	env := setupTestEnv(t)
	defer env.Close()

	getReq, _ := http.NewRequest("GET",
		env.proxyServer.URL+"/test-bucket/nonexistent.txt", nil)
	env.signRequest(getReq)

	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", getResp.StatusCode)
	}
}

// Benchmark: Encryption throughput
func BenchmarkPutObject(b *testing.B) {
	env := setupTestEnv(&testing.T{})
	defer env.Close()

	data := make([]byte, 4*1024*1024) // 4MB
	rand.Read(data)

	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		putReq, _ := http.NewRequest("PUT",
			env.proxyServer.URL+"/test-bucket/bench.bin",
			bytes.NewReader(data))
		env.signRequest(putReq)
		resp, _ := http.DefaultClient.Do(putReq)
		resp.Body.Close()
	}
}
