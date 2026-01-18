// Package s3client provides an S3 client for backend communication.
package s3client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Client is an S3 client for communicating with the backend.
type Client struct {
	endpoint   string
	region     string
	accessKey  string
	secretKey  string
	pathStyle  bool
	httpClient *http.Client
}

// ClientOptions configures the S3 client.
type ClientOptions struct {
	Endpoint           string
	Region             string
	AccessKey          string
	SecretKey          string
	PathStyle          bool
	InsecureSkipVerify bool
}

// NewClient creates a new S3 client.
func NewClient(opts ClientOptions) *Client {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.InsecureSkipVerify,
		},
	}

	return &Client{
		endpoint:  strings.TrimSuffix(opts.Endpoint, "/"),
		region:    opts.Region,
		accessKey: opts.AccessKey,
		secretKey: opts.SecretKey,
		pathStyle: opts.PathStyle,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Minute,
		},
	}
}

// Object represents an S3 object from listing.
type Object struct {
	Key          string
	LastModified time.Time
	ETag         string
	Size         int64
	StorageClass string
}

// ListObjectsV2Output represents the response from ListObjectsV2.
type ListObjectsV2Output struct {
	Contents              []Object
	IsTruncated           bool
	NextContinuationToken string
}

// GetObjectOutput represents the response from GetObject.
type GetObjectOutput struct {
	Body          io.ReadCloser
	ContentLength int64
	ContentType   string
	ETag          string
	LastModified  time.Time
	Metadata      map[string]string
}

// HeadObjectOutput represents the response from HeadObject.
type HeadObjectOutput struct {
	ContentLength int64
	ContentType   string
	ETag          string
	LastModified  time.Time
	Metadata      map[string]string
}

// PutObjectInput represents input for PutObject.
type PutObjectInput struct {
	Bucket        string
	Key           string
	Body          io.Reader
	ContentLength int64
	ContentType   string
	ContentMD5    string
	Metadata      map[string]string
	IfNoneMatch   string
}

// PutObjectOutput represents the response from PutObject.
type PutObjectOutput struct {
	ETag string
}

// CopyObjectInput represents input for CopyObject.
type CopyObjectInput struct {
	SourceBucket string
	SourceKey    string
	DestBucket   string
	DestKey      string
}

// CopyObjectOutput represents the response from CopyObject.
type CopyObjectOutput struct {
	ETag         string
	LastModified time.Time
}

// DeleteObjectsInput represents input for DeleteObjects.
type DeleteObjectsInput struct {
	Bucket  string
	Objects []ObjectIdentifier
}

// ObjectIdentifier identifies an object for deletion.
type ObjectIdentifier struct {
	Key string
}

// DeleteObjectsOutput represents the response from DeleteObjects.
type DeleteObjectsOutput struct {
	Deleted []DeletedObject
	Errors  []DeleteError
}

// DeletedObject represents a successfully deleted object.
type DeletedObject struct {
	Key string
}

// DeleteError represents a deletion error.
type DeleteError struct {
	Key     string
	Code    string
	Message string
}

// Bucket represents an S3 bucket.
type Bucket struct {
	Name         string
	CreationDate time.Time
}

// ListBucketsOutput represents the response from ListBuckets.
type ListBucketsOutput struct {
	Buckets []Bucket
}

// HeadBucket checks if a bucket exists and is accessible.
func (c *Client) HeadBucket(ctx context.Context, bucket string) error {
	req, err := c.newRequest(ctx, "HEAD", bucket, "/", nil, nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bucket check failed: %s", resp.Status)
	}

	return nil
}

// ListBuckets lists all buckets.
func (c *Client) ListBuckets(ctx context.Context) (*ListBucketsOutput, error) {
	req, err := c.newRequest(ctx, "GET", "", "/", nil, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var result struct {
		Buckets struct {
			Bucket []struct {
				Name         string `xml:"Name"`
				CreationDate string `xml:"CreationDate"`
			} `xml:"Bucket"`
		} `xml:"Buckets"`
	}

	if err := xml.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	output := &ListBucketsOutput{
		Buckets: make([]Bucket, len(result.Buckets.Bucket)),
	}

	for i, b := range result.Buckets.Bucket {
		output.Buckets[i].Name = b.Name
		if t, err := time.Parse(time.RFC3339, b.CreationDate); err == nil {
			output.Buckets[i].CreationDate = t
		}
	}

	return output, nil
}

// ListObjectsV2 lists objects in a bucket.
func (c *Client) ListObjectsV2(ctx context.Context, bucket, prefix, continuationToken string) (*ListObjectsV2Output, error) {
	query := url.Values{}
	query.Set("list-type", "2")
	if prefix != "" {
		query.Set("prefix", prefix)
	}
	if continuationToken != "" {
		query.Set("continuation-token", continuationToken)
	}

	req, err := c.newRequest(ctx, "GET", bucket, "/?"+query.Encode(), nil, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var result struct {
		IsTruncated           bool   `xml:"IsTruncated"`
		NextContinuationToken string `xml:"NextContinuationToken"`
		Contents              []struct {
			Key          string `xml:"Key"`
			LastModified string `xml:"LastModified"`
			ETag         string `xml:"ETag"`
			Size         int64  `xml:"Size"`
			StorageClass string `xml:"StorageClass"`
		} `xml:"Contents"`
	}

	if err := xml.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	output := &ListObjectsV2Output{
		IsTruncated:           result.IsTruncated,
		NextContinuationToken: result.NextContinuationToken,
		Contents:              make([]Object, len(result.Contents)),
	}

	for i, obj := range result.Contents {
		output.Contents[i] = Object{
			Key:          obj.Key,
			ETag:         obj.ETag,
			Size:         obj.Size,
			StorageClass: obj.StorageClass,
		}
		if t, err := time.Parse(time.RFC3339, obj.LastModified); err == nil {
			output.Contents[i].LastModified = t
		}
	}

	return output, nil
}

// HeadObject gets object metadata.
func (c *Client) HeadObject(ctx context.Context, bucket, key string) (*HeadObjectOutput, error) {
	req, err := c.newRequest(ctx, "HEAD", bucket, "/"+key, nil, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	output := &HeadObjectOutput{
		ContentType: resp.Header.Get("Content-Type"),
		ETag:        resp.Header.Get("ETag"),
		Metadata:    make(map[string]string),
	}

	if cl := resp.Header.Get("Content-Length"); cl != "" {
		output.ContentLength, _ = strconv.ParseInt(cl, 10, 64)
	}

	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		output.LastModified, _ = time.Parse(time.RFC1123, lm)
	}

	// Extract user metadata
	for key, values := range resp.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-amz-meta-") {
			metaKey := strings.TrimPrefix(strings.ToLower(key), "x-amz-meta-")
			if len(values) > 0 {
				output.Metadata[metaKey] = values[0]
			}
		}
	}

	return output, nil
}

// GetObjectRange retrieves a byte range of an object.
func (c *Client) GetObjectRange(ctx context.Context, bucket, key string, start, end int64) (*GetObjectOutput, error) {
	headers := map[string]string{
		"Range": fmt.Sprintf("bytes=%d-%d", start, end),
	}

	req, err := c.newRequest(ctx, "GET", bucket, "/"+key, nil, headers)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, nil
	}

	// 206 Partial Content is expected for range requests
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		defer resp.Body.Close()
		return nil, c.parseError(resp)
	}

	output := &GetObjectOutput{
		Body:        resp.Body,
		ContentType: resp.Header.Get("Content-Type"),
		ETag:        resp.Header.Get("ETag"),
		Metadata:    make(map[string]string),
	}

	if cl := resp.Header.Get("Content-Length"); cl != "" {
		output.ContentLength, _ = strconv.ParseInt(cl, 10, 64)
	}

	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		output.LastModified, _ = time.Parse(time.RFC1123, lm)
	}

	for k, values := range resp.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") {
			metaKey := strings.TrimPrefix(strings.ToLower(k), "x-amz-meta-")
			if len(values) > 0 {
				output.Metadata[metaKey] = values[0]
			}
		}
	}

	return output, nil
}

// GetObject retrieves an object.
func (c *Client) GetObject(ctx context.Context, bucket, key string) (*GetObjectOutput, error) {
	req, err := c.newRequest(ctx, "GET", bucket, "/"+key, nil, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, c.parseError(resp)
	}

	output := &GetObjectOutput{
		Body:        resp.Body,
		ContentType: resp.Header.Get("Content-Type"),
		ETag:        resp.Header.Get("ETag"),
		Metadata:    make(map[string]string),
	}

	if cl := resp.Header.Get("Content-Length"); cl != "" {
		output.ContentLength, _ = strconv.ParseInt(cl, 10, 64)
	}

	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		output.LastModified, _ = time.Parse(time.RFC1123, lm)
	}

	for key, values := range resp.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-amz-meta-") {
			metaKey := strings.TrimPrefix(strings.ToLower(key), "x-amz-meta-")
			if len(values) > 0 {
				output.Metadata[metaKey] = values[0]
			}
		}
	}

	return output, nil
}

// PutObject uploads an object.
func (c *Client) PutObject(ctx context.Context, input *PutObjectInput) (*PutObjectOutput, error) {
	headers := map[string]string{}

	if input.ContentType != "" {
		headers["Content-Type"] = input.ContentType
	} else {
		headers["Content-Type"] = "application/octet-stream"
	}

	if input.ContentLength > 0 {
		headers["Content-Length"] = strconv.FormatInt(input.ContentLength, 10)
	}

	if input.ContentMD5 != "" {
		headers["Content-MD5"] = input.ContentMD5
	}

	if input.IfNoneMatch != "" {
		headers["If-None-Match"] = input.IfNoneMatch
	}

	for k, v := range input.Metadata {
		headers["x-amz-meta-"+k] = v
	}

	req, err := c.newRequest(ctx, "PUT", input.Bucket, "/"+input.Key, input.Body, headers)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusPreconditionFailed {
		return nil, &PreconditionFailedError{}
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, c.parseError(resp)
	}

	return &PutObjectOutput{
		ETag: resp.Header.Get("ETag"),
	}, nil
}

// DeleteObject deletes an object.
func (c *Client) DeleteObject(ctx context.Context, bucket, key string) error {
	req, err := c.newRequest(ctx, "DELETE", bucket, "/"+key, nil, nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return c.parseError(resp)
	}

	return nil
}

// DeleteObjects deletes multiple objects.
func (c *Client) DeleteObjects(ctx context.Context, input *DeleteObjectsInput) (*DeleteObjectsOutput, error) {
	// Build XML body
	var buf bytes.Buffer
	buf.WriteString(`<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	for _, obj := range input.Objects {
		buf.WriteString("<Object><Key>")
		xml.EscapeText(&buf, []byte(obj.Key))
		buf.WriteString("</Key></Object>")
	}
	buf.WriteString("</Delete>")

	req, err := c.newRequest(ctx, "POST", input.Bucket, "/?delete", &buf, map[string]string{
		"Content-Type": "application/xml",
	})
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var result struct {
		Deleted []struct {
			Key string `xml:"Key"`
		} `xml:"Deleted"`
		Error []struct {
			Key     string `xml:"Key"`
			Code    string `xml:"Code"`
			Message string `xml:"Message"`
		} `xml:"Error"`
	}

	if err := xml.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	output := &DeleteObjectsOutput{
		Deleted: make([]DeletedObject, len(result.Deleted)),
		Errors:  make([]DeleteError, len(result.Error)),
	}

	for i, d := range result.Deleted {
		output.Deleted[i].Key = d.Key
	}

	for i, e := range result.Error {
		output.Errors[i] = DeleteError{
			Key:     e.Key,
			Code:    e.Code,
			Message: e.Message,
		}
	}

	return output, nil
}

// CopyObject copies an object within S3.
func (c *Client) CopyObject(ctx context.Context, input *CopyObjectInput) (*CopyObjectOutput, error) {
	copySource := "/" + input.SourceBucket + "/" + input.SourceKey

	headers := map[string]string{
		"x-amz-copy-source":        copySource,
		"x-amz-metadata-directive": "REPLACE",
	}

	req, err := c.newRequest(ctx, "PUT", input.DestBucket, "/"+input.DestKey, nil, headers)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.parseError(resp)
	}

	var result struct {
		ETag         string `xml:"ETag"`
		LastModified string `xml:"LastModified"`
	}

	if err := xml.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	output := &CopyObjectOutput{
		ETag: result.ETag,
	}

	if t, err := time.Parse(time.RFC3339, result.LastModified); err == nil {
		output.LastModified = t
	}

	return output, nil
}

// newRequest creates a new signed HTTP request.
func (c *Client) newRequest(ctx context.Context, method, bucket, path string, body io.Reader, headers map[string]string) (*http.Request, error) {
	var reqURL string

	if c.pathStyle || bucket == "" {
		if bucket != "" {
			reqURL = c.endpoint + "/" + bucket + path
		} else {
			reqURL = c.endpoint + path
		}
	} else {
		// Virtual-hosted style
		endpoint := c.endpoint
		if strings.HasPrefix(endpoint, "https://") {
			endpoint = "https://" + bucket + "." + strings.TrimPrefix(endpoint, "https://")
		} else if strings.HasPrefix(endpoint, "http://") {
			endpoint = "http://" + bucket + "." + strings.TrimPrefix(endpoint, "http://")
		}
		reqURL = endpoint + path
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Sign the request
	c.signRequest(req)

	return req, nil
}

// signRequest signs the request using AWS Signature V4.
func (c *Client) signRequest(req *http.Request) {
	now := time.Now().UTC()
	dateStr := now.Format("20060102")
	datetimeStr := now.Format("20060102T150405Z")

	req.Header.Set("x-amz-date", datetimeStr)
	req.Header.Set("Host", req.URL.Host)

	// Calculate payload hash
	var payloadHash string
	if req.Body == nil {
		payloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // SHA256 of empty string
	} else if seeker, ok := req.Body.(io.ReadSeeker); ok {
		payloadHash = calculatePayloadHash(seeker)
		seeker.Seek(0, io.SeekStart)
	} else {
		payloadHash = "UNSIGNED-PAYLOAD"
	}
	req.Header.Set("x-amz-content-sha256", payloadHash)

	// Create canonical request
	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	canonicalQuery := req.URL.RawQuery

	// Canonical headers
	signedHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	for key := range req.Header {
		lower := strings.ToLower(key)
		if lower != "host" && lower != "x-amz-content-sha256" && lower != "x-amz-date" {
			if strings.HasPrefix(lower, "x-amz-") || lower == "content-type" || lower == "content-md5" {
				signedHeaders = append(signedHeaders, lower)
			}
		}
	}
	sort.Strings(signedHeaders)

	var canonicalHeaders strings.Builder
	for _, key := range signedHeaders {
		canonicalHeaders.WriteString(key)
		canonicalHeaders.WriteString(":")
		if key == "host" {
			canonicalHeaders.WriteString(req.URL.Host)
		} else {
			canonicalHeaders.WriteString(strings.TrimSpace(req.Header.Get(key)))
		}
		canonicalHeaders.WriteString("\n")
	}

	signedHeadersStr := strings.Join(signedHeaders, ";")

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders.String(),
		signedHeadersStr,
		payloadHash,
	}, "\n")

	// Create string to sign
	credentialScope := dateStr + "/" + c.region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + datetimeStr + "\n" + credentialScope + "\n" + hashSHA256([]byte(canonicalRequest))

	// Calculate signature
	kDate := hmacSHA256([]byte("AWS4"+c.secretKey), []byte(dateStr))
	kRegion := hmacSHA256(kDate, []byte(c.region))
	kService := hmacSHA256(kRegion, []byte("s3"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := fmt.Sprintf("%x", hmacSHA256(kSigning, []byte(stringToSign)))

	// Build authorization header
	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s,SignedHeaders=%s,Signature=%s",
		c.accessKey, credentialScope, signedHeadersStr, signature)

	req.Header.Set("Authorization", authHeader)
}

// parseError parses an S3 error response.
func (c *Client) parseError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)

	var errResp struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}

	if xml.Unmarshal(body, &errResp) == nil && errResp.Code != "" {
		return &S3Error{
			StatusCode: resp.StatusCode,
			Code:       errResp.Code,
			Message:    errResp.Message,
		}
	}

	return &S3Error{
		StatusCode: resp.StatusCode,
		Code:       resp.Status,
		Message:    string(body),
	}
}

// S3Error represents an S3 API error.
type S3Error struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *S3Error) Error() string {
	return fmt.Sprintf("S3 error %d: %s - %s", e.StatusCode, e.Code, e.Message)
}

// PreconditionFailedError indicates a precondition failed (e.g., If-None-Match).
type PreconditionFailedError struct{}

func (e *PreconditionFailedError) Error() string {
	return "precondition failed"
}

// IsPreconditionFailed checks if the error is a precondition failed error.
func IsPreconditionFailed(err error) bool {
	_, ok := err.(*PreconditionFailedError)
	return ok
}
