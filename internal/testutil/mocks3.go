// Package testutil provides testing utilities including an in-memory S3 server.
package testutil

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"time"
)

// MockS3Server is an in-memory S3-compatible server for testing.
type MockS3Server struct {
	mu      sync.RWMutex
	buckets map[string]*mockBucket
	server  *httptest.Server
}

type mockBucket struct {
	name    string
	created time.Time
	objects map[string]*mockObject
}

type mockObject struct {
	key          string
	data         []byte
	contentType  string
	etag         string
	lastModified time.Time
	metadata     map[string]string
}

// NewMockS3Server creates a new mock S3 server.
func NewMockS3Server() *MockS3Server {
	s := &MockS3Server{
		buckets: make(map[string]*mockBucket),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)

	s.server = httptest.NewServer(mux)
	return s
}

// URL returns the server's URL.
func (s *MockS3Server) URL() string {
	return s.server.URL
}

// Close shuts down the server.
func (s *MockS3Server) Close() {
	s.server.Close()
}

// CreateBucket creates a bucket in the mock server.
func (s *MockS3Server) CreateBucket(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.buckets[name] = &mockBucket{
		name:    name,
		created: time.Now(),
		objects: make(map[string]*mockObject),
	}
}

// GetObjectData returns the raw data stored for an object (for test verification).
func (s *MockS3Server) GetObjectData(bucket, key string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	b, ok := s.buckets[bucket]
	if !ok {
		return nil, false
	}

	obj, ok := b.objects[key]
	if !ok {
		return nil, false
	}

	return obj.data, true
}

// ObjectCount returns the number of objects in a bucket.
func (s *MockS3Server) ObjectCount(bucket string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	b, ok := s.buckets[bucket]
	if !ok {
		return 0
	}

	return len(b.objects)
}

// SetObjectData directly sets the raw data for an object (for testing tampering).
func (s *MockS3Server) SetObjectData(bucket, key string, data []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[bucket]
	if !ok {
		return false
	}

	obj, ok := b.objects[key]
	if !ok {
		return false
	}

	obj.data = data
	return true
}

func (s *MockS3Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Parse bucket and key from path (path-style)
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)

	bucket := ""
	key := ""
	if len(parts) >= 1 {
		bucket = parts[0]
	}
	if len(parts) >= 2 {
		key = parts[1]
	}

	switch r.Method {
	case http.MethodHead:
		if key == "" {
			s.handleHeadBucket(w, r, bucket)
		} else {
			s.handleHeadObject(w, r, bucket, key)
		}
	case http.MethodGet:
		if bucket == "" {
			s.handleListBuckets(w, r)
		} else if key == "" || strings.Contains(r.URL.RawQuery, "list-type=2") {
			s.handleListObjectsV2(w, r, bucket)
		} else {
			s.handleGetObject(w, r, bucket, key)
		}
	case http.MethodPut:
		if r.Header.Get("x-amz-copy-source") != "" {
			s.handleCopyObject(w, r, bucket, key)
		} else if key == "" {
			s.handleCreateBucket(w, r, bucket)
		} else {
			s.handlePutObject(w, r, bucket, key)
		}
	case http.MethodDelete:
		if key == "" {
			s.handleDeleteBucket(w, r, bucket)
		} else {
			s.handleDeleteObject(w, r, bucket, key)
		}
	case http.MethodPost:
		if strings.Contains(r.URL.RawQuery, "delete") {
			s.handleDeleteObjects(w, r, bucket)
		} else {
			http.Error(w, "Not implemented", http.StatusNotImplemented)
		}
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *MockS3Server) handleHeadBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, ok := s.buckets[bucket]; !ok {
		s.sendError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist")
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *MockS3Server) handleCreateBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.buckets[bucket]; ok {
		s.sendError(w, http.StatusConflict, "BucketAlreadyExists", "Bucket already exists")
		return
	}

	s.buckets[bucket] = &mockBucket{
		name:    bucket,
		created: time.Now(),
		objects: make(map[string]*mockObject),
	}

	w.WriteHeader(http.StatusOK)
}

func (s *MockS3Server) handleDeleteBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[bucket]
	if !ok {
		s.sendError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist")
		return
	}

	if len(b.objects) > 0 {
		s.sendError(w, http.StatusConflict, "BucketNotEmpty", "The bucket is not empty")
		return
	}

	delete(s.buckets, bucket)
	w.WriteHeader(http.StatusNoContent)
}

func (s *MockS3Server) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

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

	for _, b := range s.buckets {
		resp.Buckets.Bucket = append(resp.Buckets.Bucket, xmlBucket{
			Name:         b.name,
			CreationDate: b.created.Format(time.RFC3339),
		})
	}

	w.Header().Set("Content-Type", "application/xml")
	xml.NewEncoder(w).Encode(resp)
}

func (s *MockS3Server) handleListObjectsV2(w http.ResponseWriter, r *http.Request, bucket string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	b, ok := s.buckets[bucket]
	if !ok {
		s.sendError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist")
		return
	}

	prefix := r.URL.Query().Get("prefix")

	type xmlContents struct {
		Key          string `xml:"Key"`
		LastModified string `xml:"LastModified"`
		ETag         string `xml:"ETag"`
		Size         int64  `xml:"Size"`
		StorageClass string `xml:"StorageClass"`
	}

	type xmlResponse struct {
		XMLName     xml.Name      `xml:"ListBucketResult"`
		Xmlns       string        `xml:"xmlns,attr"`
		Name        string        `xml:"Name"`
		Prefix      string        `xml:"Prefix"`
		IsTruncated bool          `xml:"IsTruncated"`
		Contents    []xmlContents `xml:"Contents"`
	}

	resp := xmlResponse{
		Xmlns:       "http://s3.amazonaws.com/doc/2006-03-01/",
		Name:        bucket,
		Prefix:      prefix,
		IsTruncated: false,
	}

	// Sort keys for consistent ordering
	var keys []string
	for k := range b.objects {
		if prefix == "" || strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	for _, k := range keys {
		obj := b.objects[k]
		resp.Contents = append(resp.Contents, xmlContents{
			Key:          obj.key,
			LastModified: obj.lastModified.Format(time.RFC3339),
			ETag:         obj.etag,
			Size:         int64(len(obj.data)),
			StorageClass: "STANDARD",
		})
	}

	w.Header().Set("Content-Type", "application/xml")
	xml.NewEncoder(w).Encode(resp)
}

func (s *MockS3Server) handleHeadObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	b, ok := s.buckets[bucket]
	if !ok {
		s.sendError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist")
		return
	}

	obj, ok := b.objects[key]
	if !ok {
		s.sendError(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist")
		return
	}

	w.Header().Set("Content-Type", obj.contentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(obj.data)))
	w.Header().Set("ETag", obj.etag)
	w.Header().Set("Last-Modified", obj.lastModified.Format(time.RFC1123))

	for k, v := range obj.metadata {
		w.Header().Set("x-amz-meta-"+k, v)
	}

	w.WriteHeader(http.StatusOK)
}

func (s *MockS3Server) handleGetObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	b, ok := s.buckets[bucket]
	if !ok {
		s.sendError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist")
		return
	}

	obj, ok := b.objects[key]
	if !ok {
		s.sendError(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist")
		return
	}

	// Handle Range header
	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" {
		var start, end int64
		_, _ = fmt.Sscanf(rangeHeader, "bytes=%d-%d", &start, &end)

		if start < 0 {
			start = 0
		}
		if end >= int64(len(obj.data)) || end < start {
			end = int64(len(obj.data)) - 1
		}

		data := obj.data[start : end+1]

		w.Header().Set("Content-Type", obj.contentType)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(obj.data)))
		w.Header().Set("ETag", obj.etag)
		w.Header().Set("Last-Modified", obj.lastModified.Format(time.RFC1123))
		w.WriteHeader(http.StatusPartialContent)
		w.Write(data)
		return
	}

	w.Header().Set("Content-Type", obj.contentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(obj.data)))
	w.Header().Set("ETag", obj.etag)
	w.Header().Set("Last-Modified", obj.lastModified.Format(time.RFC1123))

	for k, v := range obj.metadata {
		w.Header().Set("x-amz-meta-"+k, v)
	}

	w.WriteHeader(http.StatusOK)
	w.Write(obj.data)
}

func (s *MockS3Server) handlePutObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[bucket]
	if !ok {
		s.sendError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist")
		return
	}

	// Check If-None-Match header
	if r.Header.Get("If-None-Match") == "*" {
		if _, exists := b.objects[key]; exists {
			s.sendError(w, http.StatusPreconditionFailed, "PreconditionFailed", "Object already exists")
			return
		}
	}

	data, err := io.ReadAll(r.Body)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}

	// Calculate ETag (MD5)
	hash := md5.Sum(data)
	etag := fmt.Sprintf("\"%s\"", hex.EncodeToString(hash[:]))

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Extract metadata
	metadata := make(map[string]string)
	for k, v := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") {
			metaKey := strings.TrimPrefix(strings.ToLower(k), "x-amz-meta-")
			if len(v) > 0 {
				metadata[metaKey] = v[0]
			}
		}
	}

	b.objects[key] = &mockObject{
		key:          key,
		data:         data,
		contentType:  contentType,
		etag:         etag,
		lastModified: time.Now(),
		metadata:     metadata,
	}

	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
}

func (s *MockS3Server) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[bucket]
	if !ok {
		s.sendError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist")
		return
	}

	delete(b.objects, key)
	w.WriteHeader(http.StatusNoContent)
}

func (s *MockS3Server) handleDeleteObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[bucket]
	if !ok {
		s.sendError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist")
		return
	}

	// Parse request body
	type deleteRequest struct {
		XMLName xml.Name `xml:"Delete"`
		Objects []struct {
			Key string `xml:"Key"`
		} `xml:"Object"`
	}

	var req deleteRequest
	if err := xml.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "MalformedXML", "Invalid XML")
		return
	}

	type xmlDeleted struct {
		Key string `xml:"Key"`
	}
	type xmlResponse struct {
		XMLName xml.Name     `xml:"DeleteResult"`
		Xmlns   string       `xml:"xmlns,attr"`
		Deleted []xmlDeleted `xml:"Deleted"`
	}

	resp := xmlResponse{
		Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
	}

	for _, obj := range req.Objects {
		delete(b.objects, obj.Key)
		resp.Deleted = append(resp.Deleted, xmlDeleted{Key: obj.Key})
	}

	w.Header().Set("Content-Type", "application/xml")
	xml.NewEncoder(w).Encode(resp)
}

func (s *MockS3Server) handleCopyObject(w http.ResponseWriter, r *http.Request, destBucket, destKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Parse copy source
	copySource := r.Header.Get("x-amz-copy-source")
	copySource = strings.TrimPrefix(copySource, "/")
	parts := strings.SplitN(copySource, "/", 2)
	if len(parts) != 2 {
		s.sendError(w, http.StatusBadRequest, "InvalidArgument", "Invalid x-amz-copy-source")
		return
	}
	srcBucket, srcKey := parts[0], parts[1]

	// Get source bucket and object
	sb, ok := s.buckets[srcBucket]
	if !ok {
		s.sendError(w, http.StatusNotFound, "NoSuchBucket", "Source bucket does not exist")
		return
	}

	srcObj, ok := sb.objects[srcKey]
	if !ok {
		s.sendError(w, http.StatusNotFound, "NoSuchKey", "Source key does not exist")
		return
	}

	// Get destination bucket
	db, ok := s.buckets[destBucket]
	if !ok {
		s.sendError(w, http.StatusNotFound, "NoSuchBucket", "Destination bucket does not exist")
		return
	}

	// Copy the object
	newData := make([]byte, len(srcObj.data))
	copy(newData, srcObj.data)

	hash := md5.Sum(newData)
	etag := fmt.Sprintf("\"%s\"", hex.EncodeToString(hash[:]))
	now := time.Now()

	db.objects[destKey] = &mockObject{
		key:          destKey,
		data:         newData,
		contentType:  srcObj.contentType,
		etag:         etag,
		lastModified: now,
		metadata:     srcObj.metadata,
	}

	type xmlResponse struct {
		XMLName      xml.Name `xml:"CopyObjectResult"`
		ETag         string   `xml:"ETag"`
		LastModified string   `xml:"LastModified"`
	}

	resp := xmlResponse{
		ETag:         etag,
		LastModified: now.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/xml")
	xml.NewEncoder(w).Encode(resp)
}

func (s *MockS3Server) sendError(w http.ResponseWriter, status int, code, message string) {
	type xmlError struct {
		XMLName xml.Name `xml:"Error"`
		Code    string   `xml:"Code"`
		Message string   `xml:"Message"`
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)

	xml.NewEncoder(w).Encode(xmlError{
		Code:    code,
		Message: message,
	})
}

// TestHelper provides helper functions for tests.
type TestHelper struct {
	MockS3    *MockS3Server
	ProxyURL  string
	AdminURL  string
	MasterKey []byte
}

// NewTestHelper creates a complete test environment.
func NewTestHelper() *TestHelper {
	mockS3 := NewMockS3Server()
	mockS3.CreateBucket("test-bucket")

	// Generate a test master key
	masterKey := bytes.Repeat([]byte{0x42}, 32)

	return &TestHelper{
		MockS3:    mockS3,
		MasterKey: masterKey,
	}
}

// Close cleans up the test environment.
func (h *TestHelper) Close() {
	if h.MockS3 != nil {
		h.MockS3.Close()
	}
}
