// Package proxy implements the S3 encryption proxy.
package proxy

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/s3-crypt-proxy/internal/auth"
	"github.com/s3-crypt-proxy/internal/crypto"
	"github.com/s3-crypt-proxy/internal/metrics"
	"github.com/s3-crypt-proxy/internal/s3client"
)

// Proxy handles S3 requests with encryption.
type Proxy struct {
	backend        *s3client.Client
	km             *crypto.KeyManager
	encryptor      *crypto.Encryptor
	auth           *auth.Authenticator
	metrics        *metrics.Metrics
	chunkSize      int
	logger         *slog.Logger
	allowedBuckets map[string]bool // nil means all buckets allowed
}

// ProxyOptions configures the proxy.
type ProxyOptions struct {
	Backend        *s3client.Client
	KeyMgr         *crypto.KeyManager
	Auth           *auth.Authenticator
	Metrics        *metrics.Metrics
	ChunkSize      int
	Logger         *slog.Logger
	AllowedBuckets []string // empty means all buckets allowed
}

// NewProxy creates a new S3 encryption proxy.
func NewProxy(opts ProxyOptions) *Proxy {
	if opts.ChunkSize <= 0 {
		opts.ChunkSize = crypto.DefaultChunkSize
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	// Build allowed buckets map
	var allowedBuckets map[string]bool
	if len(opts.AllowedBuckets) > 0 {
		allowedBuckets = make(map[string]bool)
		for _, b := range opts.AllowedBuckets {
			allowedBuckets[b] = true
		}
	}

	return &Proxy{
		backend:        opts.Backend,
		km:             opts.KeyMgr,
		encryptor:      crypto.NewEncryptor(opts.KeyMgr, opts.ChunkSize),
		auth:           opts.Auth,
		metrics:        opts.Metrics,
		chunkSize:      opts.ChunkSize,
		logger:         opts.Logger,
		allowedBuckets: allowedBuckets,
	}
}

// ServeHTTP handles incoming S3 requests.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	p.metrics.IncActiveRequests()
	defer p.metrics.DecActiveRequests()

	// Authenticate request
	authResult := p.auth.Authenticate(r)
	if !authResult.Authenticated {
		p.metrics.RecordAuthFailure(authResult.Error)
		p.logger.Debug("authentication failed",
			"method", r.Method,
			"path", r.URL.Path,
			"error", authResult.Error,
			"remote_addr", r.RemoteAddr)
		p.sendError(w, http.StatusForbidden, "AccessDenied", authResult.Error)
		return
	}

	// Check if key is loaded
	if !p.km.IsLoaded() {
		p.sendError(w, http.StatusServiceUnavailable, "ServiceUnavailable", "Encryption key not loaded")
		return
	}

	// Parse bucket and key from path
	bucket, key := p.parsePath(r)

	// Check bucket access (skip for ListBuckets which has no bucket)
	if bucket != "" && !p.isBucketAllowed(bucket) {
		p.sendError(w, http.StatusForbidden, "AccessDenied", "Access to bucket not allowed")
		p.metrics.RecordRequest(r.Method, "AccessDenied", http.StatusForbidden, time.Since(start), 0, 0, bucket, key)
		return
	}

	// Route request
	var status int
	var bytesIn, bytesOut int64
	var operation string
	var err error

	switch r.Method {
	case http.MethodHead:
		if key == "" {
			operation = "HeadBucket"
			status, err = p.handleHeadBucket(w, r, bucket)
		} else {
			operation = "HeadObject"
			status, bytesOut, err = p.handleHeadObject(w, r, bucket, key)
		}

	case http.MethodGet:
		if bucket == "" {
			operation = "ListBuckets"
			status, err = p.handleListBuckets(w, r)
		} else if key == "" || strings.Contains(r.URL.RawQuery, "list-type=2") {
			operation = "ListObjectsV2"
			status, err = p.handleListObjectsV2(w, r, bucket)
		} else {
			operation = "GetObject"
			status, bytesOut, err = p.handleGetObject(w, r, bucket, key)
		}

	case http.MethodPut:
		if r.Header.Get("x-amz-copy-source") != "" {
			operation = "CopyObject"
			status, err = p.handleCopyObject(w, r, bucket, key)
		} else {
			operation = "PutObject"
			status, bytesIn, err = p.handlePutObject(w, r, bucket, key)
		}

	case http.MethodDelete:
		if key == "" {
			operation = "DeleteBucket"
			p.sendError(w, http.StatusNotImplemented, "NotImplemented", "DeleteBucket not supported")
			status = http.StatusNotImplemented
		} else {
			operation = "DeleteObject"
			status, err = p.handleDeleteObject(w, r, bucket, key)
		}

	case http.MethodPost:
		if strings.Contains(r.URL.RawQuery, "delete") {
			operation = "DeleteObjects"
			status, err = p.handleDeleteObjects(w, r, bucket)
		} else {
			p.sendError(w, http.StatusNotImplemented, "NotImplemented", "Operation not supported")
			status = http.StatusNotImplemented
		}

	default:
		p.sendError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed")
		status = http.StatusMethodNotAllowed
	}

	duration := time.Since(start)
	p.metrics.RecordRequest(r.Method, operation, status, duration, bytesIn, bytesOut, bucket, key)

	if err != nil {
		p.logger.Error("request failed",
			"operation", operation,
			"bucket", bucket,
			"key", key,
			"error", err,
			"duration", duration)
	} else {
		p.logger.Debug("request completed",
			"operation", operation,
			"bucket", bucket,
			"key", key,
			"status", status,
			"duration", duration)
	}
}

func (p *Proxy) parsePath(r *http.Request) (bucket, key string) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)

	if len(parts) >= 1 {
		bucket = parts[0]
	}
	if len(parts) >= 2 {
		key = parts[1]
	}

	return bucket, key
}

// isBucketAllowed checks if the bucket is in the allowed list.
// Returns true if no allowed list is configured (all buckets allowed).
func (p *Proxy) isBucketAllowed(bucket string) bool {
	if p.allowedBuckets == nil {
		return true // No restrictions
	}
	return p.allowedBuckets[bucket]
}

func (p *Proxy) handleHeadBucket(w http.ResponseWriter, r *http.Request, bucket string) (int, error) {
	ctx := r.Context()

	if err := p.backend.HeadBucket(ctx, bucket); err != nil {
		if s3Err, ok := err.(*s3client.S3Error); ok {
			p.sendError(w, s3Err.StatusCode, s3Err.Code, s3Err.Message)
			return s3Err.StatusCode, err
		}
		p.sendError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return http.StatusInternalServerError, err
	}

	w.WriteHeader(http.StatusOK)
	return http.StatusOK, nil
}

func (p *Proxy) handleListBuckets(w http.ResponseWriter, r *http.Request) (int, error) {
	// Build XML response
	type xmlBucket struct {
		Name         string `xml:"Name"`
		CreationDate string `xml:"CreationDate"`
	}
	type xmlBuckets struct {
		Bucket []xmlBucket `xml:"Bucket"`
	}
	type xmlResponse struct {
		XMLName xml.Name   `xml:"ListAllMyBucketsResult"`
		Xmlns   string     `xml:"xmlns,attr"`
		Buckets xmlBuckets `xml:"Buckets"`
	}

	resp := xmlResponse{
		Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
	}

	// If allowed buckets are configured, return only those (hardcoded list)
	// This avoids needing ListBuckets permission on the backend
	if p.allowedBuckets != nil {
		for bucket := range p.allowedBuckets {
			resp.Buckets.Bucket = append(resp.Buckets.Bucket, xmlBucket{
				Name:         bucket,
				CreationDate: time.Now().UTC().Format(time.RFC3339),
			})
		}
	} else {
		// No restrictions - query backend for bucket list
		ctx := r.Context()
		output, err := p.backend.ListBuckets(ctx)
		if err != nil {
			if s3Err, ok := err.(*s3client.S3Error); ok {
				p.sendError(w, s3Err.StatusCode, s3Err.Code, s3Err.Message)
				return s3Err.StatusCode, err
			}
			p.sendError(w, http.StatusInternalServerError, "InternalError", err.Error())
			return http.StatusInternalServerError, err
		}

		for _, b := range output.Buckets {
			resp.Buckets.Bucket = append(resp.Buckets.Bucket, xmlBucket{
				Name:         b.Name,
				CreationDate: b.CreationDate.Format(time.RFC3339),
			})
		}
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_ = xml.NewEncoder(w).Encode(resp)

	return http.StatusOK, nil
}

func (p *Proxy) handleListObjectsV2(w http.ResponseWriter, r *http.Request, bucket string) (int, error) {
	ctx := r.Context()

	prefix := r.URL.Query().Get("prefix")
	continuationToken := r.URL.Query().Get("continuation-token")

	output, err := p.backend.ListObjectsV2(ctx, bucket, prefix, continuationToken)
	if err != nil {
		if s3Err, ok := err.(*s3client.S3Error); ok {
			p.sendError(w, s3Err.StatusCode, s3Err.Code, s3Err.Message)
			return s3Err.StatusCode, err
		}
		p.sendError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return http.StatusInternalServerError, err
	}

	// Adjust sizes to account for encryption overhead
	type xmlContents struct {
		Key          string `xml:"Key"`
		LastModified string `xml:"LastModified"`
		ETag         string `xml:"ETag"`
		Size         int64  `xml:"Size"`
		StorageClass string `xml:"StorageClass,omitempty"`
	}

	type xmlResponse struct {
		XMLName               xml.Name      `xml:"ListBucketResult"`
		Xmlns                 string        `xml:"xmlns,attr"`
		Name                  string        `xml:"Name"`
		Prefix                string        `xml:"Prefix"`
		IsTruncated           bool          `xml:"IsTruncated"`
		ContinuationToken     string        `xml:"ContinuationToken,omitempty"`
		NextContinuationToken string        `xml:"NextContinuationToken,omitempty"`
		Contents              []xmlContents `xml:"Contents"`
	}

	resp := xmlResponse{
		Xmlns:                 "http://s3.amazonaws.com/doc/2006-03-01/",
		Name:                  bucket,
		Prefix:                prefix,
		IsTruncated:           output.IsTruncated,
		ContinuationToken:     continuationToken,
		NextContinuationToken: output.NextContinuationToken,
	}

	for _, obj := range output.Contents {
		// Skip our internal state file from listings
		if strings.HasSuffix(obj.Key, "_objcryptproxy___.json") {
			continue
		}

		// Estimate original size (rough approximation)
		// The actual size is stored in encrypted metadata
		estimatedSize := obj.Size
		if estimatedSize > int64(crypto.HeaderSize+crypto.SaltSize+100) {
			estimatedSize = crypto.CalculatePlaintextSize(obj.Size, 100)
		}

		resp.Contents = append(resp.Contents, xmlContents{
			Key:          obj.Key,
			LastModified: obj.LastModified.Format(time.RFC3339),
			ETag:         obj.ETag,
			Size:         estimatedSize,
			StorageClass: obj.StorageClass,
		})
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_ = xml.NewEncoder(w).Encode(resp)

	return http.StatusOK, nil
}

func (p *Proxy) handleHeadObject(w http.ResponseWriter, r *http.Request, bucket, key string) (int, int64, error) {
	ctx := r.Context()

	// First check if object exists with a backend HEAD request
	headOutput, err := p.backend.HeadObject(ctx, bucket, key)
	if err != nil {
		if s3Err, ok := err.(*s3client.S3Error); ok {
			p.sendError(w, s3Err.StatusCode, s3Err.Code, s3Err.Message)
			return s3Err.StatusCode, 0, err
		}
		p.sendError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return http.StatusInternalServerError, 0, err
	}

	if headOutput == nil {
		p.sendError(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
		return http.StatusNotFound, 0, nil
	}

	// Fetch entire object to decrypt and compute ETag
	// This is necessary because ETag must be computed from plaintext content
	output, err := p.backend.GetObject(ctx, bucket, key)
	if err != nil {
		if s3Err, ok := err.(*s3client.S3Error); ok {
			p.sendError(w, s3Err.StatusCode, s3Err.Code, s3Err.Message)
			return s3Err.StatusCode, 0, err
		}
		p.sendError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return http.StatusInternalServerError, 0, err
	}

	if output == nil {
		p.sendError(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
		return http.StatusNotFound, 0, nil
	}

	defer output.Body.Close()

	// Create decrypt reader
	decryptReader, err := crypto.NewDecryptReader(output.Body, p.km, key, p.chunkSize)
	if err != nil {
		p.metrics.RecordEncryptionError("decrypt_init")
		p.sendError(w, http.StatusInternalServerError, "InternalError", "Failed to initialize decryption")
		return http.StatusInternalServerError, 0, err
	}

	metadata := decryptReader.Metadata()

	// Read all decrypted content to compute ETag
	plaintext, err := io.ReadAll(decryptReader)
	if err != nil {
		p.metrics.RecordEncryptionError("decrypt_stream")
		p.sendError(w, http.StatusInternalServerError, "InternalError", "Failed to decrypt object")
		return http.StatusInternalServerError, 0, err
	}

	// Compute ETag from plaintext MD5 (matches PutObject/GetObject)
	plaintextHash := md5.Sum(plaintext)
	plaintextETag := fmt.Sprintf("\"%s\"", hex.EncodeToString(plaintextHash[:]))

	w.Header().Set("Content-Type", metadata.ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(plaintext)))
	w.Header().Set("ETag", plaintextETag)
	w.Header().Set("Last-Modified", output.LastModified.UTC().Format(time.RFC1123))
	w.WriteHeader(http.StatusOK)

	return http.StatusOK, 0, nil
}

func (p *Proxy) handleGetObject(w http.ResponseWriter, r *http.Request, bucket, key string) (int, int64, error) {
	ctx := r.Context()
	startTime := time.Now()

	output, err := p.backend.GetObject(ctx, bucket, key)
	if err != nil {
		if s3Err, ok := err.(*s3client.S3Error); ok {
			p.sendError(w, s3Err.StatusCode, s3Err.Code, s3Err.Message)
			return s3Err.StatusCode, 0, err
		}
		p.sendError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return http.StatusInternalServerError, 0, err
	}

	if output == nil {
		p.sendError(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
		return http.StatusNotFound, 0, nil
	}

	defer output.Body.Close()

	// Create decrypt reader
	decryptReader, err := crypto.NewDecryptReader(output.Body, p.km, key, p.chunkSize)
	if err != nil {
		p.metrics.RecordEncryptionError("decrypt_init")
		p.sendError(w, http.StatusInternalServerError, "InternalError", "Failed to initialize decryption")
		return http.StatusInternalServerError, 0, err
	}

	metadata := decryptReader.Metadata()

	// Read all decrypted content to compute ETag
	// PBS chunks are typically ~4MB so this is acceptable
	plaintext, err := io.ReadAll(decryptReader)
	if err != nil {
		p.metrics.RecordEncryptionError("decrypt_stream")
		p.sendError(w, http.StatusInternalServerError, "InternalError", "Failed to decrypt object")
		return http.StatusInternalServerError, 0, err
	}

	// Compute ETag from plaintext MD5 (matches PutObject)
	plaintextHash := md5.Sum(plaintext)
	plaintextETag := fmt.Sprintf("\"%s\"", hex.EncodeToString(plaintextHash[:]))

	w.Header().Set("Content-Type", metadata.ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(plaintext)))
	w.Header().Set("ETag", plaintextETag)
	w.Header().Set("Last-Modified", output.LastModified.UTC().Format(time.RFC1123))
	w.WriteHeader(http.StatusOK)

	// Write decrypted content
	bytesWritten, err := w.Write(plaintext)
	if err != nil {
		return http.StatusInternalServerError, int64(bytesWritten), err
	}

	p.metrics.RecordDecryption(int64(bytesWritten), time.Since(startTime))

	return http.StatusOK, int64(bytesWritten), nil
}

func (p *Proxy) handlePutObject(w http.ResponseWriter, r *http.Request, bucket, key string) (int, int64, error) {
	ctx := r.Context()
	startTime := time.Now()

	// Read content length
	contentLength, _ := strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64)
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Read entire body for encryption
	// For very large files, streaming would be better, but PBS chunks are typically ~4MB
	body, err := io.ReadAll(r.Body)
	if err != nil {
		p.sendError(w, http.StatusInternalServerError, "InternalError", "Failed to read request body")
		return http.StatusInternalServerError, 0, err
	}

	// Compute ETag from plaintext MD5 (standard S3 behavior)
	plaintextHash := md5.Sum(body)
	plaintextETag := fmt.Sprintf("\"%s\"", hex.EncodeToString(plaintextHash[:]))

	// Create metadata
	metadata := &crypto.ObjectMetadata{
		ContentType:   contentType,
		ContentLength: int64(len(body)),
	}

	// Encrypt
	encrypted, err := p.encryptor.Encrypt(key, body, metadata)
	if err != nil {
		p.metrics.RecordEncryptionError("encrypt")
		p.sendError(w, http.StatusInternalServerError, "InternalError", "Encryption failed")
		return http.StatusInternalServerError, 0, err
	}

	// Upload to backend
	input := &s3client.PutObjectInput{
		Bucket:        bucket,
		Key:           key,
		Body:          bytes.NewReader(encrypted),
		ContentLength: int64(len(encrypted)),
		ContentType:   "application/octet-stream",
	}

	// Handle If-None-Match for PBS's upload_no_replace
	if r.Header.Get("If-None-Match") == "*" {
		input.IfNoneMatch = "*"
	}

	_, err = p.backend.PutObject(ctx, input)
	if err != nil {
		if s3client.IsPreconditionFailed(err) {
			p.sendError(w, http.StatusPreconditionFailed, "PreconditionFailed", "Object already exists")
			return http.StatusPreconditionFailed, contentLength, nil
		}
		if s3Err, ok := err.(*s3client.S3Error); ok {
			p.sendError(w, s3Err.StatusCode, s3Err.Code, s3Err.Message)
			return s3Err.StatusCode, 0, err
		}
		p.sendError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return http.StatusInternalServerError, 0, err
	}

	p.metrics.RecordEncryption(contentLength, time.Since(startTime))

	// Return ETag computed from plaintext (consistent with GetObject)
	w.Header().Set("ETag", plaintextETag)
	w.WriteHeader(http.StatusOK)

	return http.StatusOK, contentLength, nil
}

func (p *Proxy) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucket, key string) (int, error) {
	ctx := r.Context()

	if err := p.backend.DeleteObject(ctx, bucket, key); err != nil {
		if s3Err, ok := err.(*s3client.S3Error); ok {
			p.sendError(w, s3Err.StatusCode, s3Err.Code, s3Err.Message)
			return s3Err.StatusCode, err
		}
		p.sendError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return http.StatusInternalServerError, err
	}

	w.WriteHeader(http.StatusNoContent)
	return http.StatusNoContent, nil
}

func (p *Proxy) handleDeleteObjects(w http.ResponseWriter, r *http.Request, bucket string) (int, error) {
	ctx := r.Context()

	// Parse request body
	type deleteRequest struct {
		XMLName xml.Name `xml:"Delete"`
		Objects []struct {
			Key string `xml:"Key"`
		} `xml:"Object"`
	}

	var req deleteRequest
	if err := xml.NewDecoder(r.Body).Decode(&req); err != nil {
		p.sendError(w, http.StatusBadRequest, "MalformedXML", "Invalid XML in request body")
		return http.StatusBadRequest, err
	}

	input := &s3client.DeleteObjectsInput{
		Bucket:  bucket,
		Objects: make([]s3client.ObjectIdentifier, len(req.Objects)),
	}
	for i, obj := range req.Objects {
		input.Objects[i].Key = obj.Key
	}

	output, err := p.backend.DeleteObjects(ctx, input)
	if err != nil {
		if s3Err, ok := err.(*s3client.S3Error); ok {
			p.sendError(w, s3Err.StatusCode, s3Err.Code, s3Err.Message)
			return s3Err.StatusCode, err
		}
		p.sendError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return http.StatusInternalServerError, err
	}

	// Build response
	type xmlDeleted struct {
		Key string `xml:"Key"`
	}
	type xmlError struct {
		Key     string `xml:"Key"`
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	type xmlResponse struct {
		XMLName xml.Name     `xml:"DeleteResult"`
		Xmlns   string       `xml:"xmlns,attr"`
		Deleted []xmlDeleted `xml:"Deleted"`
		Error   []xmlError   `xml:"Error"`
	}

	resp := xmlResponse{
		Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
	}

	for _, d := range output.Deleted {
		resp.Deleted = append(resp.Deleted, xmlDeleted{Key: d.Key})
	}
	for _, e := range output.Errors {
		resp.Error = append(resp.Error, xmlError{
			Key:     e.Key,
			Code:    e.Code,
			Message: e.Message,
		})
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_ = xml.NewEncoder(w).Encode(resp)

	return http.StatusOK, nil
}

func (p *Proxy) handleCopyObject(w http.ResponseWriter, r *http.Request, destBucket, destKey string) (int, error) {
	ctx := r.Context()
	startTime := time.Now()

	// Parse copy source
	copySource := r.Header.Get("x-amz-copy-source")
	copySource = strings.TrimPrefix(copySource, "/")
	parts := strings.SplitN(copySource, "/", 2)
	if len(parts) != 2 {
		p.sendError(w, http.StatusBadRequest, "InvalidArgument", "Invalid x-amz-copy-source")
		return http.StatusBadRequest, nil
	}
	srcBucket, srcKey := parts[0], parts[1]

	// Fetch and decrypt source object
	srcOutput, err := p.backend.GetObject(ctx, srcBucket, srcKey)
	if err != nil {
		if s3Err, ok := err.(*s3client.S3Error); ok {
			p.sendError(w, s3Err.StatusCode, s3Err.Code, s3Err.Message)
			return s3Err.StatusCode, err
		}
		p.sendError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return http.StatusInternalServerError, err
	}

	if srcOutput == nil {
		p.sendError(w, http.StatusNotFound, "NoSuchKey", "Source key does not exist")
		return http.StatusNotFound, nil
	}

	defer srcOutput.Body.Close()

	// Read and decrypt source
	encryptedSrc, err := io.ReadAll(srcOutput.Body)
	if err != nil {
		p.sendError(w, http.StatusInternalServerError, "InternalError", "Failed to read source object")
		return http.StatusInternalServerError, err
	}

	plaintext, metadata, err := p.encryptor.Decrypt(srcKey, encryptedSrc)
	if err != nil {
		p.metrics.RecordEncryptionError("decrypt_copy")
		p.sendError(w, http.StatusInternalServerError, "InternalError", "Failed to decrypt source object")
		return http.StatusInternalServerError, err
	}

	// Re-encrypt with new key (new salt = new nonce)
	encrypted, err := p.encryptor.Encrypt(destKey, plaintext, metadata)
	if err != nil {
		p.metrics.RecordEncryptionError("encrypt_copy")
		p.sendError(w, http.StatusInternalServerError, "InternalError", "Encryption failed")
		return http.StatusInternalServerError, err
	}

	// Upload to destination
	input := &s3client.PutObjectInput{
		Bucket:        destBucket,
		Key:           destKey,
		Body:          bytes.NewReader(encrypted),
		ContentLength: int64(len(encrypted)),
		ContentType:   "application/octet-stream",
	}

	output, err := p.backend.PutObject(ctx, input)
	if err != nil {
		if s3Err, ok := err.(*s3client.S3Error); ok {
			p.sendError(w, s3Err.StatusCode, s3Err.Code, s3Err.Message)
			return s3Err.StatusCode, err
		}
		p.sendError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return http.StatusInternalServerError, err
	}

	p.metrics.RecordDecryption(int64(len(plaintext)), time.Since(startTime)/2)
	p.metrics.RecordEncryption(int64(len(plaintext)), time.Since(startTime)/2)

	// Build response
	type xmlResponse struct {
		XMLName      xml.Name `xml:"CopyObjectResult"`
		ETag         string   `xml:"ETag"`
		LastModified string   `xml:"LastModified"`
	}

	resp := xmlResponse{
		ETag:         output.ETag,
		LastModified: time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_ = xml.NewEncoder(w).Encode(resp)

	return http.StatusOK, nil
}

func (p *Proxy) sendError(w http.ResponseWriter, status int, code, message string) {
	type xmlError struct {
		XMLName xml.Name `xml:"Error"`
		Code    string   `xml:"Code"`
		Message string   `xml:"Message"`
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)

	_ = xml.NewEncoder(w).Encode(xmlError{
		Code:    code,
		Message: message,
	})
}
