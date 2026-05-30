package httpserver

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"litewaf-api/internal/app"
	"litewaf-api/internal/auth"
	"litewaf-api/internal/config"
	"litewaf-api/internal/model"
	"litewaf-api/internal/store"
)

func testServer(t *testing.T) http.Handler {
	t.Helper()
	cfg := config.Config{
		AppName:               "LiteWaf API",
		Env:                   "test",
		HTTPAddr:              ":0",
		GatewayConfigPath:     t.TempDir() + "/active.json",
		PublishOperator:       "test",
		AuthTokenSecret:       "test-secret",
		AuthTokenTTL:          3600000000000,
		GatewayIngestionToken: "gateway-secret",
		MetricsEnabled:        true,
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	dataStore := store.NewMemoryStore()
	hash, err := auth.HashPassword("secret123")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := dataStore.EnsureUser(t.Context(), model.User{
		Username:     "admin",
		PasswordHash: hash,
		Role:         "admin",
		Enabled:      true,
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	application := app.New(cfg, dataStore)
	mux := http.NewServeMux()
	registerRoutes(mux, logger, application)
	return mux
}

func adminToken(t *testing.T, handler http.Handler) string {
	t.Helper()
	body := bytes.NewBufferString(`{"username":"admin","password":"secret123"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	if response.AccessToken == "" {
		t.Fatal("expected access token")
	}
	return response.AccessToken
}

func withToken(req *http.Request, token string) *http.Request {
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func TestSiteCRUD(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	body := bytes.NewBufferString(`{"name":"Example","host":"example.test","upstream":"http://upstream:8080","mode":"protect"}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/sites", body), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/sites", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d", rec.Code)
	}
	var response struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(response.Items) != 1 {
		t.Fatalf("expected 1 site, got %d", len(response.Items))
	}
}

func TestCreateSiteValidation(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)
	body := bytes.NewBufferString(`{"name":"Bad","host":"","upstream":"nope","mode":"protect"}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/sites", body), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestNotFound(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)
	req := withToken(httptest.NewRequest(http.MethodGet, "/api/v1/sites/404", nil), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestProtectedEndpointRequiresToken(t *testing.T) {
	handler := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sites", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestObservabilityIngestionAndQueries(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/access-logs", bytes.NewBufferString(`{"request_id":"req-1","site_id":1,"host":"example.test","method":"GET","uri":"/login","status":403,"duration_ms":12,"client_ip":"192.0.2.10","user_agent":"curl","disposition":"blocked"}`))
	req.Header.Set("Authorization", "Bearer gateway-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("ingest access status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/ingest/waf-events", bytes.NewBufferString(`{"request_id":"req-1","site_id":1,"event_type":"rule","rule_id":7,"rule_type":"sqli","target":"args","action":"block","disposition":"blocked","client_ip":"192.0.2.10","method":"GET","uri":"/login","summary":"matched"}`))
	req.Header.Set("Authorization", "Bearer gateway-secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("ingest waf status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/access-logs?site_id=1&client_ip=192.0.2.10", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list access status = %d body=%s", rec.Code, rec.Body.String())
	}
	var accessResponse struct {
		Items []model.AccessLog `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&accessResponse); err != nil {
		t.Fatalf("decode access logs: %v", err)
	}
	if len(accessResponse.Items) != 1 || accessResponse.Items[0].RequestID != "req-1" {
		t.Fatalf("unexpected access logs: %+v", accessResponse.Items)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/attack-logs?rule_id=7", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list attack status = %d body=%s", rec.Code, rec.Body.String())
	}
	var attackResponse struct {
		Items []model.WAFEvent `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&attackResponse); err != nil {
		t.Fatalf("decode attack logs: %v", err)
	}
	if len(attackResponse.Items) != 1 || attackResponse.Items[0].RuleID != 7 {
		t.Fatalf("unexpected attack logs: %+v", attackResponse.Items)
	}
}

func TestAdvancedWAFEventIngestionQueryAndSummary(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/waf-events", bytes.NewBufferString(`{"request_id":"req-advanced","site_id":2,"event_type":"score-threshold","rule_id":9,"rule_type":"custom","target":"body_json","advanced_target":"body_json","action":"block","disposition":"blocked","client_ip":"192.0.2.20","method":"POST","uri":"/api/login","summary":"matched body value","normalized_value":"select password","score":220,"threshold":200,"matched_rule_ids":"8,9","body_metadata":"content_type=application/json","upload_metadata":"","ban_reason":"score-threshold","ban_duration_sec":300,"ban_remaining_sec":299}`))
	req.Header.Set("Authorization", "Bearer gateway-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("ingest advanced waf status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/attack-logs?advanced_target=body_json&min_score=200", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("query advanced attack status = %d body=%s", rec.Code, rec.Body.String())
	}
	var attackResponse struct {
		Items []model.WAFEvent `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&attackResponse); err != nil {
		t.Fatalf("decode attack logs: %v", err)
	}
	if len(attackResponse.Items) != 1 || attackResponse.Items[0].Score != 220 || attackResponse.Items[0].AdvancedTarget != "body_json" {
		t.Fatalf("unexpected advanced attack logs: %+v", attackResponse.Items)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/observability/summary", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("summary status = %d body=%s", rec.Code, rec.Body.String())
	}
	var summaryResponse struct {
		Item model.ObservabilitySummary `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&summaryResponse); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if summaryResponse.Item.ScoreBlocks != 1 || summaryResponse.Item.BodyDetections != 1 {
		t.Fatalf("unexpected advanced summary: %+v", summaryResponse.Item)
	}
}

func TestObservabilityIngestionRequiresGatewayToken(t *testing.T) {
	handler := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/access-logs", bytes.NewBufferString(`{"request_id":"req-1","method":"GET","uri":"/","status":200,"disposition":"proxied"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestObservabilityEmptyQueryAndSummary(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	req := withToken(httptest.NewRequest(http.MethodGet, "/api/v1/access-logs?client_ip=198.51.100.99", nil), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("empty access status = %d body=%s", rec.Code, rec.Body.String())
	}
	var listResponse struct {
		Items []model.AccessLog `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&listResponse); err != nil {
		t.Fatalf("decode empty access logs: %v", err)
	}
	if len(listResponse.Items) != 0 {
		t.Fatalf("expected empty list, got %+v", listResponse.Items)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/observability/summary", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("summary status = %d body=%s", rec.Code, rec.Body.String())
	}
	var summaryResponse struct {
		Item model.ObservabilitySummary `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&summaryResponse); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if summaryResponse.Item.Requests != 0 || len(summaryResponse.Item.TopIPs) != 0 {
		t.Fatalf("unexpected summary: %+v", summaryResponse.Item)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	handler := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("litewaf_api_up 1")) {
		t.Fatalf("metrics body missing api up metric: %s", rec.Body.String())
	}
}
