// Package metrics provides Prometheus metrics and live WebUI for monitoring.
package metrics

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds all the metrics for the proxy.
type Metrics struct {
	// Request counters
	RequestsTotal *prometheus.CounterVec

	// Byte counters
	BytesEncrypted prometheus.Counter
	BytesDecrypted prometheus.Counter

	// Error counters
	EncryptionErrors *prometheus.CounterVec
	AuthFailures     *prometheus.CounterVec

	// Histograms
	RequestDuration   *prometheus.HistogramVec
	EncryptionLatency *prometheus.HistogramVec

	// Gauges
	KeyLoaded      prometheus.Gauge
	ActiveRequests prometheus.Gauge
	ConnectionPool prometheus.Gauge

	// Internal tracking for live UI
	mu             sync.RWMutex
	recentRequests []RequestRecord
	recentErrors   []ErrorRecord
	startTime      time.Time
	requestCount   atomic.Int64
	errorCount     atomic.Int64
}

// RequestRecord represents a recent request for live UI.
type RequestRecord struct {
	Time      time.Time
	Method    string
	Operation string
	Bucket    string
	Key       string
	Status    int
	Duration  time.Duration
	BytesIn   int64
	BytesOut  int64
}

// ErrorRecord represents a recent error for live UI.
type ErrorRecord struct {
	Time    time.Time
	Type    string
	Message string
}

var (
	metricsOnce   sync.Once
	globalMetrics *Metrics
)

// New creates a new Metrics instance with all metrics registered.
// It uses singleton pattern for Prometheus metrics to avoid duplicate registration.
func New() *Metrics {
	metricsOnce.Do(func() {
		globalMetrics = &Metrics{
			RequestsTotal: prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Name: "s3_crypt_proxy_requests_total",
					Help: "Total number of requests processed",
				},
				[]string{"method", "operation", "status"},
			),

			BytesEncrypted: prometheus.NewCounter(prometheus.CounterOpts{
				Name: "s3_crypt_proxy_bytes_encrypted_total",
				Help: "Total bytes encrypted",
			}),

			BytesDecrypted: prometheus.NewCounter(prometheus.CounterOpts{
				Name: "s3_crypt_proxy_bytes_decrypted_total",
				Help: "Total bytes decrypted",
			}),

			EncryptionErrors: prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Name: "s3_crypt_proxy_encryption_errors_total",
					Help: "Total encryption/decryption errors",
				},
				[]string{"type"},
			),

			AuthFailures: prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Name: "s3_crypt_proxy_auth_failures_total",
					Help: "Total authentication failures",
				},
				[]string{"reason"},
			),

			RequestDuration: prometheus.NewHistogramVec(
				prometheus.HistogramOpts{
					Name:    "s3_crypt_proxy_request_duration_seconds",
					Help:    "Request duration in seconds",
					Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
				},
				[]string{"operation"},
			),

			EncryptionLatency: prometheus.NewHistogramVec(
				prometheus.HistogramOpts{
					Name:    "s3_crypt_proxy_encryption_duration_seconds",
					Help:    "Encryption/decryption duration in seconds",
					Buckets: prometheus.ExponentialBuckets(0.0001, 2, 15),
				},
				[]string{"operation"},
			),

			KeyLoaded: prometheus.NewGauge(prometheus.GaugeOpts{
				Name: "s3_crypt_proxy_key_loaded",
				Help: "Whether an encryption key is loaded (1=yes, 0=no)",
			}),

			ActiveRequests: prometheus.NewGauge(prometheus.GaugeOpts{
				Name: "s3_crypt_proxy_active_requests",
				Help: "Number of currently active requests",
			}),

			ConnectionPool: prometheus.NewGauge(prometheus.GaugeOpts{
				Name: "s3_crypt_proxy_backend_connection_pool_size",
				Help: "Backend connection pool size",
			}),

			recentRequests: make([]RequestRecord, 0, 100),
			recentErrors:   make([]ErrorRecord, 0, 50),
			startTime:      time.Now(),
		}

		// Register all metrics
		prometheus.MustRegister(
			globalMetrics.RequestsTotal,
			globalMetrics.BytesEncrypted,
			globalMetrics.BytesDecrypted,
			globalMetrics.EncryptionErrors,
			globalMetrics.AuthFailures,
			globalMetrics.RequestDuration,
			globalMetrics.EncryptionLatency,
			globalMetrics.KeyLoaded,
			globalMetrics.ActiveRequests,
			globalMetrics.ConnectionPool,
		)
	})

	// Return a new instance that shares the prometheus collectors but has its own state
	return &Metrics{
		RequestsTotal:     globalMetrics.RequestsTotal,
		BytesEncrypted:    globalMetrics.BytesEncrypted,
		BytesDecrypted:    globalMetrics.BytesDecrypted,
		EncryptionErrors:  globalMetrics.EncryptionErrors,
		AuthFailures:      globalMetrics.AuthFailures,
		RequestDuration:   globalMetrics.RequestDuration,
		EncryptionLatency: globalMetrics.EncryptionLatency,
		KeyLoaded:         globalMetrics.KeyLoaded,
		ActiveRequests:    globalMetrics.ActiveRequests,
		ConnectionPool:    globalMetrics.ConnectionPool,
		recentRequests:    make([]RequestRecord, 0, 100),
		recentErrors:      make([]ErrorRecord, 0, 50),
		startTime:         time.Now(),
	}
}

// RecordRequest records a completed request.
func (m *Metrics) RecordRequest(method, operation string, status int, duration time.Duration, bytesIn, bytesOut int64, bucket, key string) {
	statusStr := statusToString(status)

	m.RequestsTotal.WithLabelValues(method, operation, statusStr).Inc()
	m.RequestDuration.WithLabelValues(operation).Observe(duration.Seconds())
	m.requestCount.Add(1)

	// Store for live UI (keep last 100)
	m.mu.Lock()
	record := RequestRecord{
		Time:      time.Now(),
		Method:    method,
		Operation: operation,
		Bucket:    bucket,
		Key:       key,
		Status:    status,
		Duration:  duration,
		BytesIn:   bytesIn,
		BytesOut:  bytesOut,
	}

	m.recentRequests = append(m.recentRequests, record)
	if len(m.recentRequests) > 100 {
		m.recentRequests = m.recentRequests[1:]
	}
	m.mu.Unlock()
}

// RecordEncryption records encryption metrics.
func (m *Metrics) RecordEncryption(bytes int64, duration time.Duration) {
	m.BytesEncrypted.Add(float64(bytes))
	m.EncryptionLatency.WithLabelValues("encrypt").Observe(duration.Seconds())
}

// RecordDecryption records decryption metrics.
func (m *Metrics) RecordDecryption(bytes int64, duration time.Duration) {
	m.BytesDecrypted.Add(float64(bytes))
	m.EncryptionLatency.WithLabelValues("decrypt").Observe(duration.Seconds())
}

// RecordEncryptionError records an encryption error.
func (m *Metrics) RecordEncryptionError(errorType string) {
	m.EncryptionErrors.WithLabelValues(errorType).Inc()
	m.recordError("encryption", errorType)
}

// RecordAuthFailure records an authentication failure.
func (m *Metrics) RecordAuthFailure(reason string) {
	m.AuthFailures.WithLabelValues(reason).Inc()
	m.recordError("auth", reason)
}

// SetKeyLoaded sets the key loaded status.
func (m *Metrics) SetKeyLoaded(loaded bool) {
	if loaded {
		m.KeyLoaded.Set(1)
	} else {
		m.KeyLoaded.Set(0)
	}
}

// IncActiveRequests increments active requests.
func (m *Metrics) IncActiveRequests() {
	m.ActiveRequests.Inc()
}

// DecActiveRequests decrements active requests.
func (m *Metrics) DecActiveRequests() {
	m.ActiveRequests.Dec()
}

// GetStats returns statistics for the live UI.
func (m *Metrics) GetStats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Calculate requests per second over last minute
	now := time.Now()
	oneMinuteAgo := now.Add(-time.Minute)
	var recentCount int
	for _, r := range m.recentRequests {
		if r.Time.After(oneMinuteAgo) {
			recentCount++
		}
	}

	recentErrors := make([]ErrorRecord, len(m.recentErrors))
	copy(recentErrors, m.recentErrors)

	recentRequests := make([]RequestRecord, len(m.recentRequests))
	copy(recentRequests, m.recentRequests)

	return Stats{
		Uptime:         time.Since(m.startTime),
		TotalRequests:  m.requestCount.Load(),
		TotalErrors:    m.errorCount.Load(),
		RequestsPerMin: float64(recentCount),
		RecentRequests: recentRequests,
		RecentErrors:   recentErrors,
	}
}

func (m *Metrics) recordError(errType, message string) {
	m.errorCount.Add(1)

	m.mu.Lock()
	record := ErrorRecord{
		Time:    time.Now(),
		Type:    errType,
		Message: message,
	}

	m.recentErrors = append(m.recentErrors, record)
	if len(m.recentErrors) > 50 {
		m.recentErrors = m.recentErrors[1:]
	}
	m.mu.Unlock()
}

// Stats holds statistics for the live UI.
type Stats struct {
	Uptime         time.Duration
	TotalRequests  int64
	TotalErrors    int64
	RequestsPerMin float64
	RecentRequests []RequestRecord
	RecentErrors   []ErrorRecord
}

func statusToString(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "2xx"
	case status >= 300 && status < 400:
		return "3xx"
	case status >= 400 && status < 500:
		return "4xx"
	case status >= 500:
		return "5xx"
	default:
		return "unknown"
	}
}
