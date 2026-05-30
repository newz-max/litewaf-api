package httpserver

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type httpMetrics struct {
	mu              sync.Mutex
	requests        map[string]int64
	errors          map[string]int64
	durationTotalMS map[string]int64
}

var apiMetrics = &httpMetrics{
	requests:        map[string]int64{},
	errors:          map[string]int64{},
	durationTotalMS: map[string]int64{},
}

func recordHTTPMetric(method string, path string, status int, duration time.Duration) {
	key := metricKey(method, path)
	apiMetrics.mu.Lock()
	defer apiMetrics.mu.Unlock()
	apiMetrics.requests[key]++
	apiMetrics.durationTotalMS[key] += duration.Milliseconds()
	if status >= 500 {
		apiMetrics.errors[key]++
	}
}

func (h handlers) metrics(w http.ResponseWriter, r *http.Request) {
	if !h.app.Config.MetricsEnabled {
		http.NotFound(w, r)
		return
	}
	apiMetrics.mu.Lock()
	defer apiMetrics.mu.Unlock()
	var builder strings.Builder
	builder.WriteString("# HELP litewaf_api_up API process health.\n")
	builder.WriteString("# TYPE litewaf_api_up gauge\n")
	builder.WriteString("litewaf_api_up 1\n")
	builder.WriteString("# HELP litewaf_api_http_requests_total API HTTP requests.\n")
	builder.WriteString("# TYPE litewaf_api_http_requests_total counter\n")
	for key, value := range apiMetrics.requests {
		method, path := splitMetricKey(key)
		builder.WriteString(fmt.Sprintf("litewaf_api_http_requests_total{method=%q,path=%q} %d\n", method, path, value))
	}
	builder.WriteString("# HELP litewaf_api_http_errors_total API HTTP 5xx responses.\n")
	builder.WriteString("# TYPE litewaf_api_http_errors_total counter\n")
	for key, value := range apiMetrics.errors {
		method, path := splitMetricKey(key)
		builder.WriteString(fmt.Sprintf("litewaf_api_http_errors_total{method=%q,path=%q} %d\n", method, path, value))
	}
	builder.WriteString("# HELP litewaf_api_http_request_duration_milliseconds_total API HTTP request duration total.\n")
	builder.WriteString("# TYPE litewaf_api_http_request_duration_milliseconds_total counter\n")
	for key, value := range apiMetrics.durationTotalMS {
		method, path := splitMetricKey(key)
		builder.WriteString(fmt.Sprintf("litewaf_api_http_request_duration_milliseconds_total{method=%q,path=%q} %d\n", method, path, value))
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(builder.String()))
}

func metricKey(method string, path string) string {
	return method + "\x00" + path
}

func splitMetricKey(key string) (string, string) {
	parts := strings.SplitN(key, "\x00", 2)
	if len(parts) != 2 {
		return "", key
	}
	return parts[0], parts[1]
}
