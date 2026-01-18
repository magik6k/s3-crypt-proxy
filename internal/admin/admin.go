// Package admin provides the admin API for key management and metrics.
package admin

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/s3-crypt-proxy/internal/auth"
	"github.com/s3-crypt-proxy/internal/crypto"
	"github.com/s3-crypt-proxy/internal/metrics"
)

// Server handles admin API requests.
type Server struct {
	km      *crypto.KeyManager
	auth    *auth.AdminAuthenticator
	mux     *http.ServeMux
	metrics *metrics.Metrics
}

// NewServer creates a new admin server.
func NewServer(km *crypto.KeyManager, adminToken string, m *metrics.Metrics) *Server {
	s := &Server{
		km:      km,
		auth:    auth.NewAdminAuthenticator(adminToken),
		mux:     http.NewServeMux(),
		metrics: m,
	}

	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	// Health checks (no auth required)
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/readyz", s.handleReadyz)

	// Metrics (no auth required)
	s.mux.Handle("/metrics", promhttp.Handler())

	// Live WebUI (no auth required - read-only)
	s.mux.HandleFunc("/", s.handleLiveUI)
	s.mux.HandleFunc("/api/v1/metrics/live", s.handleLiveMetrics)

	// Key management (auth required)
	s.mux.HandleFunc("/api/v1/key/load", s.withAuth(s.handleKeyLoad))
	s.mux.HandleFunc("/api/v1/key", s.withAuth(s.handleKey))
	s.mux.HandleFunc("/api/v1/key/status", s.withAuth(s.handleKeyStatus))
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) withAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := s.auth.Authenticate(r); err != nil {
			s.metrics.RecordAuthFailure("admin")
			http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.km.IsLoaded() {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("not ready: encryption key not loaded"))
	}
}

type keyLoadRequest struct {
	MasterKey string `json:"master_key"`
}

type keyLoadResponse struct {
	Status string `json:"status"`
	KeyID  string `json:"key_id"`
}

func (s *Server) handleKeyLoad(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req keyLoadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	keyBytes, err := base64.StdEncoding.DecodeString(req.MasterKey)
	if err != nil {
		http.Error(w, `{"error": "invalid base64 encoding"}`, http.StatusBadRequest)
		return
	}

	if err := s.km.LoadKey(keyBytes); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	s.metrics.SetKeyLoaded(true)

	resp := keyLoadResponse{
		Status: "loaded",
		KeyID:  s.km.KeyID(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, `{"error": "method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	s.km.ClearKey()
	s.metrics.SetKeyLoaded(false)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status": "cleared"}`))
}

type keyStatusResponse struct {
	Loaded   bool   `json:"loaded"`
	KeyID    string `json:"key_id,omitempty"`
	LoadedAt string `json:"loaded_at,omitempty"`
}

func (s *Server) handleKeyStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error": "method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	resp := keyStatusResponse{
		Loaded: s.km.IsLoaded(),
	}

	if resp.Loaded {
		resp.KeyID = s.km.KeyID()
		resp.LoadedAt = s.km.LoadedAt().Format(time.RFC3339)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleLiveMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error": "method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	stats := s.metrics.GetStats()

	resp := struct {
		Uptime         string  `json:"uptime"`
		TotalRequests  int64   `json:"total_requests"`
		TotalErrors    int64   `json:"total_errors"`
		RequestsPerMin float64 `json:"requests_per_min"`
		KeyLoaded      bool    `json:"key_loaded"`
	}{
		Uptime:         stats.Uptime.Round(time.Second).String(),
		TotalRequests:  stats.TotalRequests,
		TotalErrors:    stats.TotalErrors,
		RequestsPerMin: stats.RequestsPerMin,
		KeyLoaded:      s.km.IsLoaded(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleLiveUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(liveUIHTML))
}

const liveUIHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>S3-Crypt-Proxy Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            color: #eee;
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 {
            font-size: 1.8em;
            margin-bottom: 20px;
            color: #00d4ff;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            display: inline-block;
        }
        .status-ok { background: #00ff88; box-shadow: 0 0 10px #00ff88; }
        .status-error { background: #ff4444; box-shadow: 0 0 10px #ff4444; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            border: 1px solid #0f3460;
        }
        .stat-label {
            color: #888;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #00d4ff;
            margin-top: 5px;
        }
        .stat-value.error { color: #ff6b6b; }
        .section {
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #0f3460;
        }
        .section h2 {
            font-size: 1.2em;
            margin-bottom: 15px;
            color: #00d4ff;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #0f3460;
        }
        th { color: #888; font-weight: normal; font-size: 0.85em; text-transform: uppercase; }
        td { font-family: 'Monaco', 'Menlo', monospace; font-size: 0.9em; }
        .status-2xx { color: #00ff88; }
        .status-4xx { color: #ffaa00; }
        .status-5xx { color: #ff4444; }
        .method { color: #00d4ff; }
        .duration { color: #888; }
        .key-status { display: inline-flex; align-items: center; gap: 8px; }
        #chart-container {
            height: 150px;
            position: relative;
            margin-top: 10px;
        }
        canvas { width: 100% !important; height: 100% !important; }
        .refresh-indicator {
            position: fixed;
            top: 20px;
            right: 20px;
            color: #666;
            font-size: 0.8em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>
            <span class="status-indicator" id="status-light"></span>
            S3-Crypt-Proxy
        </h1>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Uptime</div>
                <div class="stat-value" id="uptime">--</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Requests</div>
                <div class="stat-value" id="total-requests">--</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Requests/min</div>
                <div class="stat-value" id="rpm">--</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Errors</div>
                <div class="stat-value error" id="errors">--</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Key Status</div>
                <div class="stat-value">
                    <span class="key-status">
                        <span class="status-indicator" id="key-light"></span>
                        <span id="key-status">--</span>
                    </span>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Request Rate</h2>
            <div id="chart-container">
                <canvas id="chart"></canvas>
            </div>
        </div>

        <div class="section">
            <h2>Recent Requests</h2>
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Method</th>
                        <th>Operation</th>
                        <th>Status</th>
                        <th>Duration</th>
                    </tr>
                </thead>
                <tbody id="requests-body">
                </tbody>
            </table>
        </div>
    </div>

    <div class="refresh-indicator">Updates every 2s</div>

    <script>
        const chartData = [];
        const maxDataPoints = 60;

        function formatDuration(ns) {
            if (ns < 1000) return ns + 'ns';
            if (ns < 1000000) return (ns / 1000).toFixed(1) + 'us';
            if (ns < 1000000000) return (ns / 1000000).toFixed(1) + 'ms';
            return (ns / 1000000000).toFixed(2) + 's';
        }

        function formatTime(isoString) {
            const d = new Date(isoString);
            return d.toLocaleTimeString();
        }

        function getStatusClass(status) {
            if (status >= 200 && status < 300) return 'status-2xx';
            if (status >= 400 && status < 500) return 'status-4xx';
            return 'status-5xx';
        }

        let chart = null;

        function initChart() {
            const canvas = document.getElementById('chart');
            const ctx = canvas.getContext('2d');

            function drawChart() {
                const rect = canvas.parentElement.getBoundingClientRect();
                canvas.width = rect.width * window.devicePixelRatio;
                canvas.height = rect.height * window.devicePixelRatio;
                ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

                const width = rect.width;
                const height = rect.height;

                ctx.clearRect(0, 0, width, height);

                if (chartData.length < 2) return;

                const maxVal = Math.max(...chartData, 1);
                const step = width / (maxDataPoints - 1);

                ctx.beginPath();
                ctx.strokeStyle = '#00d4ff';
                ctx.lineWidth = 2;

                for (let i = 0; i < chartData.length; i++) {
                    const x = i * step;
                    const y = height - (chartData[i] / maxVal) * (height - 20);
                    if (i === 0) ctx.moveTo(x, y);
                    else ctx.lineTo(x, y);
                }
                ctx.stroke();

                // Fill area
                ctx.lineTo((chartData.length - 1) * step, height);
                ctx.lineTo(0, height);
                ctx.closePath();
                ctx.fillStyle = 'rgba(0, 212, 255, 0.1)';
                ctx.fill();
            }

            return { draw: drawChart };
        }

        async function fetchMetrics() {
            try {
                const resp = await fetch('/api/v1/metrics/live');
                const data = await resp.json();

                document.getElementById('uptime').textContent = data.uptime;
                document.getElementById('total-requests').textContent = data.total_requests.toLocaleString();
                document.getElementById('rpm').textContent = data.requests_per_min.toFixed(1);
                document.getElementById('errors').textContent = data.total_errors.toLocaleString();

                const keyLoaded = data.key_loaded;
                document.getElementById('key-status').textContent = keyLoaded ? 'Loaded' : 'Not Loaded';
                document.getElementById('key-light').className = 'status-indicator ' + (keyLoaded ? 'status-ok' : 'status-error');
                document.getElementById('status-light').className = 'status-indicator ' + (keyLoaded ? 'status-ok' : 'status-error');

                // Update chart
                chartData.push(data.requests_per_min);
                if (chartData.length > maxDataPoints) chartData.shift();
                if (chart) chart.draw();

            } catch (err) {
                console.error('Failed to fetch metrics:', err);
            }
        }

        function init() {
            chart = initChart();
            fetchMetrics();
            setInterval(fetchMetrics, 2000);
            window.addEventListener('resize', () => chart && chart.draw());
        }

        init();
    </script>
</body>
</html>`
