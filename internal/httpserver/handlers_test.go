package httpserver

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"litewaf-api/internal/app"
	"litewaf-api/internal/auth"
	"litewaf-api/internal/config"
	"litewaf-api/internal/model"
	"litewaf-api/internal/publish"
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

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/protection/overview", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("overview status = %d body=%s", rec.Code, rec.Body.String())
	}
	var overviewResponse struct {
		Item model.ProtectionOverview `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&overviewResponse); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	if len(overviewResponse.Item.Modules) != 7 {
		t.Fatalf("expected implemented module rows, got %+v", overviewResponse.Item.Modules)
	}
	if len(overviewResponse.Item.Risks) != 0 {
		t.Fatalf("empty overview fabricated risks: %+v", overviewResponse.Item.Risks)
	}
	for _, module := range overviewResponse.Item.Modules {
		if len(module.Warnings) != 0 {
			t.Fatalf("empty overview fabricated warnings: %+v", module)
		}
		if module.Key == "cc-protection" || module.Key == "access-control" || module.Key == "upload-protection" || module.Key == "bot-protection" || module.Key == "dynamic-protection" {
			if module.Rules != 0 || module.Enabled != 0 {
				t.Fatalf("empty overview fabricated module data: %+v", module)
			}
		}
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

func TestCCProtectionRulesEmptyList(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	req := withToken(httptest.NewRequest(http.MethodGet, "/api/v1/cc-protection/rules", nil), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Items []model.ProtectionRule `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode cc protection rules: %v", err)
	}
	if len(response.Items) != 0 {
		t.Fatalf("expected empty list, got %+v", response.Items)
	}
}

func TestAccessControlRulesEmptyList(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	req := withToken(httptest.NewRequest(http.MethodGet, "/api/v1/access-control/rules", nil), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Items []model.ProtectionRule `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode access control rules: %v", err)
	}
	if len(response.Items) != 0 {
		t.Fatalf("expected empty list, got %+v", response.Items)
	}
}

func TestUploadProtectionRulesEmptyList(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	req := withToken(httptest.NewRequest(http.MethodGet, "/api/v1/upload-protection/rules", nil), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Items []model.ProtectionRule `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode upload protection rules: %v", err)
	}
	if len(response.Items) != 0 {
		t.Fatalf("expected empty list, got %+v", response.Items)
	}
}

func TestBotProtectionRulesEmptyList(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	req := withToken(httptest.NewRequest(http.MethodGet, "/api/v1/bot-protection/rules", nil), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Items []model.ProtectionRule `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode bot protection rules: %v", err)
	}
	if len(response.Items) != 0 {
		t.Fatalf("expected empty list, got %+v", response.Items)
	}
}

func TestDynamicProtectionRulesEmptyList(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	req := withToken(httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-protection/rules", nil), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Items []model.ProtectionRule `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode dynamic protection rules: %v", err)
	}
	if len(response.Items) != 0 {
		t.Fatalf("expected empty list, got %+v", response.Items)
	}
}

func TestBotProtectionRuleWriteLifecycleAndAudit(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	body := bytes.NewBufferString(`{"name":"Admin challenge","site_id":3,"priority":70,"match":{"path":"/admin","path_match":"prefix","methods":["get","POST"]},"challenge":{"mode":"js-challenge","verify_ttl_sec":600,"failure_action":"block"}}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/bot-protection/rules", body), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create bot protection status = %d body=%s", rec.Code, rec.Body.String())
	}
	var createResponse struct {
		Item model.ProtectionRule `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&createResponse); err != nil {
		t.Fatalf("decode create bot protection: %v", err)
	}
	if createResponse.Item.Module != "bot-protection" || createResponse.Item.Category != "challenge" {
		t.Fatalf("unexpected bot protection identity: %+v", createResponse.Item)
	}
	if createResponse.Item.Match.Path != "/admin" || createResponse.Item.Match.PathMatch != "prefix" || len(createResponse.Item.Match.Methods) != 2 {
		t.Fatalf("unexpected bot protection match: %+v", createResponse.Item.Match)
	}
	if createResponse.Item.Challenge == nil || createResponse.Item.Challenge.Mode != "js-challenge" || createResponse.Item.Challenge.VerifyTTL != 600 || createResponse.Item.Challenge.FailureAction != "block" {
		t.Fatalf("unexpected bot protection challenge: %+v", createResponse.Item.Challenge)
	}
	if createResponse.Item.Action.Type != "block" || createResponse.Item.Priority != 70 {
		t.Fatalf("unexpected bot protection action: %+v", createResponse.Item)
	}

	updateBody := bytes.NewBufferString(`{"name":"Login observe","site_id":3,"enabled":false,"match":{"path":"/login","path_match":"exact","methods":["GET","POST"]},"challenge":{"mode":"js-challenge","verify_ttl_sec":300,"failure_action":"log-only"}}`)
	req = withToken(httptest.NewRequest(http.MethodPut, "/api/v1/bot-protection/rules/"+strconv.FormatInt(createResponse.Item.ID, 10), updateBody), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update bot protection status = %d body=%s", rec.Code, rec.Body.String())
	}
	var updateResponse struct {
		Item model.ProtectionRule `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&updateResponse); err != nil {
		t.Fatalf("decode update bot protection: %v", err)
	}
	if updateResponse.Item.Enabled || updateResponse.Item.Match.Path != "/login" || updateResponse.Item.Action.Type != "log-only" {
		t.Fatalf("unexpected updated bot protection: %+v", updateResponse.Item)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs?resource_type=bot_protection_rule", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit list status = %d body=%s", rec.Code, rec.Body.String())
	}
	var auditResponse struct {
		Items []model.AuditLog `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&auditResponse); err != nil {
		t.Fatalf("decode audit logs: %v", err)
	}
	if len(auditResponse.Items) < 2 {
		t.Fatalf("expected create and update audit logs, got %+v", auditResponse.Items)
	}

	req = withToken(httptest.NewRequest(http.MethodDelete, "/api/v1/bot-protection/rules/"+strconv.FormatInt(createResponse.Item.ID, 10), nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete bot protection status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDynamicProtectionRuleWriteLifecycleAndAudit(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	body := bytes.NewBufferString(`{"name":"Admin dynamic token","site_id":3,"priority":65,"category":"dynamic-token","match":{"path":"/admin","path_match":"prefix","methods":["get"]},"dynamic":{"mode":"dynamic-token","token_ttl_sec":600,"token_placement":"cookie","failure_action":"block"}}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-protection/rules", body), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create dynamic protection status = %d body=%s", rec.Code, rec.Body.String())
	}
	var createResponse struct {
		Item model.ProtectionRule `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&createResponse); err != nil {
		t.Fatalf("decode create dynamic protection: %v", err)
	}
	if createResponse.Item.Module != "dynamic-protection" || createResponse.Item.Category != "dynamic-token" {
		t.Fatalf("unexpected dynamic protection identity: %+v", createResponse.Item)
	}
	if createResponse.Item.Dynamic == nil || createResponse.Item.Dynamic.TokenTTL != 600 || createResponse.Item.Dynamic.TokenPlacement != "cookie" || createResponse.Item.Dynamic.FailureAction != "block" {
		t.Fatalf("unexpected dynamic protection config: %+v", createResponse.Item.Dynamic)
	}
	if createResponse.Item.Action.Type != "block" || createResponse.Item.Priority != 65 {
		t.Fatalf("unexpected dynamic protection action: %+v", createResponse.Item)
	}

	updateBody := bytes.NewBufferString(`{"name":"Waiting room","site_id":3,"enabled":false,"category":"waiting-room","match":{"path":"/","path_match":"prefix","methods":[]},"dynamic":{"mode":"waiting-room","queue_capacity":20,"admission_ttl_sec":120,"retry_interval_sec":5,"overflow_action":"waiting-room"}}`)
	req = withToken(httptest.NewRequest(http.MethodPut, "/api/v1/dynamic-protection/rules/"+strconv.FormatInt(createResponse.Item.ID, 10), updateBody), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update dynamic protection status = %d body=%s", rec.Code, rec.Body.String())
	}
	var updateResponse struct {
		Item model.ProtectionRule `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&updateResponse); err != nil {
		t.Fatalf("decode update dynamic protection: %v", err)
	}
	if updateResponse.Item.Enabled || updateResponse.Item.Category != "waiting-room" || updateResponse.Item.Dynamic.QueueCapacity != 20 || updateResponse.Item.Action.Type != "waiting-room" {
		t.Fatalf("unexpected updated dynamic protection: %+v", updateResponse.Item)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs?resource_type=dynamic_protection_rule", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit list status = %d body=%s", rec.Code, rec.Body.String())
	}
	var auditResponse struct {
		Items []model.AuditLog `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&auditResponse); err != nil {
		t.Fatalf("decode audit logs: %v", err)
	}
	if len(auditResponse.Items) < 2 {
		t.Fatalf("expected create and update audit logs, got %+v", auditResponse.Items)
	}

	req = withToken(httptest.NewRequest(http.MethodDelete, "/api/v1/dynamic-protection/rules/"+strconv.FormatInt(createResponse.Item.ID, 10), nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete dynamic protection status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestBotProtectionWriteValidationAndAuthorization(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	invalidBodies := []string{
		`{"name":"bad","match":{"path":"admin","path_match":"prefix"},"challenge":{"mode":"js-challenge","verify_ttl_sec":300,"failure_action":"block"}}`,
		`{"name":"bad","match":{"path":"/admin","path_match":"regex"},"challenge":{"mode":"js-challenge","verify_ttl_sec":300,"failure_action":"block"}}`,
		`{"name":"bad","match":{"path":"/admin","path_match":"prefix","methods":["TRACE"]},"challenge":{"mode":"js-challenge","verify_ttl_sec":300,"failure_action":"block"}}`,
		`{"name":"bad","match":{"path":"/admin","path_match":"prefix"},"challenge":{"mode":"captcha","verify_ttl_sec":300,"failure_action":"block"}}`,
		`{"name":"bad","match":{"path":"/admin","path_match":"prefix"},"challenge":{"mode":"js-challenge","verify_ttl_sec":0,"failure_action":"block"}}`,
		`{"name":"bad","match":{"path":"/admin","path_match":"prefix"},"challenge":{"mode":"js-challenge","verify_ttl_sec":300,"failure_action":"captcha"}}`,
		`{"name":"bad","priority":-1,"match":{"path":"/admin","path_match":"prefix"},"challenge":{"mode":"js-challenge","verify_ttl_sec":300,"failure_action":"block"}}`,
	}
	for _, body := range invalidBodies {
		req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/bot-protection/rules", bytes.NewBufferString(body)), token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %s status = %d body=%s", body, rec.Code, rec.Body.String())
		}
	}

	readonlyToken, _, err := auth.IssueToken("test-secret", "readonly", 99, "readonly", 3600000000000)
	if err != nil {
		t.Fatalf("issue readonly token: %v", err)
	}
	validBody := bytes.NewBufferString(`{"name":"Admin challenge","match":{"path":"/admin","path_match":"prefix"},"challenge":{"mode":"js-challenge","verify_ttl_sec":300,"failure_action":"block"}}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/bot-protection/rules", validBody), readonlyToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly create status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDynamicProtectionWriteValidationAndAuthorization(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	invalidBodies := []string{
		`{"name":"bad","category":"dynamic-token","match":{"path":"admin","path_match":"prefix"},"dynamic":{"mode":"dynamic-token","token_ttl_sec":300,"token_placement":"cookie","failure_action":"block"}}`,
		`{"name":"bad","category":"dynamic-token","match":{"path":"/admin","path_match":"regex"},"dynamic":{"mode":"dynamic-token","token_ttl_sec":300,"token_placement":"cookie","failure_action":"block"}}`,
		`{"name":"bad","category":"dynamic-token","match":{"path":"/admin","path_match":"prefix","methods":["TRACE"]},"dynamic":{"mode":"dynamic-token","token_ttl_sec":300,"token_placement":"cookie","failure_action":"block"}}`,
		`{"name":"bad","category":"dynamic-token","match":{"path":"/admin","path_match":"prefix"},"dynamic":{"mode":"dynamic-token","token_ttl_sec":0,"token_placement":"cookie","failure_action":"block"}}`,
		`{"name":"bad","category":"dynamic-token","match":{"path":"/admin","path_match":"prefix"},"dynamic":{"mode":"dynamic-token","token_ttl_sec":300,"token_placement":"body","failure_action":"block"}}`,
		`{"name":"bad","category":"page-mutation","match":{"path":"/","path_match":"prefix"},"dynamic":{"mode":"page-mutation","mutation_marker":"middle","mutation_max_bytes":1000},"action":{"type":"log-only"}}`,
		`{"name":"bad","category":"waiting-room","match":{"path":"/","path_match":"prefix"},"dynamic":{"mode":"waiting-room","queue_capacity":0,"admission_ttl_sec":300,"retry_interval_sec":5,"overflow_action":"waiting-room"}}`,
	}
	for _, body := range invalidBodies {
		req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-protection/rules", bytes.NewBufferString(body)), token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %s status = %d body=%s", body, rec.Code, rec.Body.String())
		}
	}

	readonlyToken, _, err := auth.IssueToken("test-secret", "readonly", 99, "readonly", 3600000000000)
	if err != nil {
		t.Fatalf("issue readonly token: %v", err)
	}
	validBody := bytes.NewBufferString(`{"name":"Admin dynamic token","category":"dynamic-token","match":{"path":"/admin","path_match":"prefix"},"dynamic":{"mode":"dynamic-token","token_ttl_sec":300,"token_placement":"cookie","failure_action":"block"}}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-protection/rules", validBody), readonlyToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly create status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestUploadProtectionRuleWriteLifecycleAndAudit(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	body := bytes.NewBufferString(`{"name":"Script upload block","site_id":3,"priority":70,"match":{"path":"/upload","path_match":"prefix","methods":["post"]},"upload":{"extensions":[".php","JSP"],"max_bytes":2097152},"action":{"type":"block"}}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/upload-protection/rules", body), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create upload protection status = %d body=%s", rec.Code, rec.Body.String())
	}
	var createResponse struct {
		Item model.ProtectionRule `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&createResponse); err != nil {
		t.Fatalf("decode create upload protection: %v", err)
	}
	if createResponse.Item.Module != "upload-protection" || createResponse.Item.Category != "upload" {
		t.Fatalf("unexpected upload protection identity: %+v", createResponse.Item)
	}
	if createResponse.Item.Match.Path != "/upload" || createResponse.Item.Match.PathMatch != "prefix" || len(createResponse.Item.Match.Methods) != 1 {
		t.Fatalf("unexpected upload protection match: %+v", createResponse.Item.Match)
	}
	if createResponse.Item.Upload == nil || len(createResponse.Item.Upload.Extensions) != 2 || createResponse.Item.Upload.Extensions[0] != "php" || createResponse.Item.Upload.MaxBytes != 2097152 {
		t.Fatalf("unexpected upload protection payload: %+v", createResponse.Item.Upload)
	}
	if createResponse.Item.Action.Type != "block" || createResponse.Item.Priority != 70 {
		t.Fatalf("unexpected upload protection action: %+v", createResponse.Item)
	}

	updateBody := bytes.NewBufferString(`{"name":"Avatar observe","site_id":3,"enabled":false,"match":{"path":"/avatar","path_match":"exact","methods":["POST"]},"upload":{"max_bytes":524288},"action":{"type":"log-only"}}`)
	req = withToken(httptest.NewRequest(http.MethodPut, "/api/v1/upload-protection/rules/"+strconv.FormatInt(createResponse.Item.ID, 10), updateBody), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update upload protection status = %d body=%s", rec.Code, rec.Body.String())
	}
	var updateResponse struct {
		Item model.ProtectionRule `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&updateResponse); err != nil {
		t.Fatalf("decode update upload protection: %v", err)
	}
	if updateResponse.Item.Enabled || updateResponse.Item.Match.Path != "/avatar" || updateResponse.Item.Action.Type != "log-only" {
		t.Fatalf("unexpected updated upload protection: %+v", updateResponse.Item)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs?resource_type=upload_protection_rule", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit list status = %d body=%s", rec.Code, rec.Body.String())
	}
	var auditResponse struct {
		Items []model.AuditLog `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&auditResponse); err != nil {
		t.Fatalf("decode audit logs: %v", err)
	}
	if len(auditResponse.Items) < 2 {
		t.Fatalf("expected create and update audit logs, got %+v", auditResponse.Items)
	}

	req = withToken(httptest.NewRequest(http.MethodDelete, "/api/v1/upload-protection/rules/"+strconv.FormatInt(createResponse.Item.ID, 10), nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete upload protection status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestUploadProtectionWriteValidationAndAuthorization(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	invalidBodies := []string{
		`{"name":"bad","match":{"path":"upload","path_match":"prefix"},"upload":{"extensions":["php"]},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"path":"/upload","path_match":"regex"},"upload":{"extensions":["php"]},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"path":"/upload","path_match":"prefix","methods":["TRACE"]},"upload":{"extensions":["php"]},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"path":"/upload","path_match":"prefix"},"upload":{"extensions":["../php"]},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"path":"/upload","path_match":"prefix"},"upload":{"max_bytes":-1},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"path":"/upload","path_match":"prefix"},"upload":{},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"path":"/upload","path_match":"prefix"},"upload":{"extensions":["php"]},"action":{"type":"ban"}}`,
		`{"name":"bad","priority":-1,"match":{"path":"/upload","path_match":"prefix"},"upload":{"extensions":["php"]},"action":{"type":"block"}}`,
	}
	for _, body := range invalidBodies {
		req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/upload-protection/rules", bytes.NewBufferString(body)), token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %s status = %d body=%s", body, rec.Code, rec.Body.String())
		}
	}

	readonlyToken, _, err := auth.IssueToken("test-secret", "readonly", 99, "readonly", 3600000000000)
	if err != nil {
		t.Fatalf("issue readonly token: %v", err)
	}
	validBody := bytes.NewBufferString(`{"name":"Upload block","match":{"path":"/upload","path_match":"prefix"},"upload":{"extensions":["php"]},"action":{"type":"block"}}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/upload-protection/rules", validBody), readonlyToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly create status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAccessControlRulesMapAccessLists(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	body := bytes.NewBufferString(`{"name":"Admin block","kind":"blacklist","target":"uri","value":"/admin","match_operator":"prefix","action":"block","site_id":7,"priority":80}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/access-lists", body), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create access list status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/access-control/rules?site_id=7&enabled=true", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list access control status = %d body=%s", rec.Code, rec.Body.String())
	}
	var listResponse struct {
		Items []model.ProtectionRule `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&listResponse); err != nil {
		t.Fatalf("decode access control list: %v", err)
	}
	if len(listResponse.Items) != 1 {
		t.Fatalf("expected 1 access control rule, got %+v", listResponse.Items)
	}
	item := listResponse.Items[0]
	if item.Module != "access-control" || item.Category != "access-control" || item.Action.Type != "block" {
		t.Fatalf("unexpected access control identity: %+v", item)
	}
	if item.Match.Target != "path" || item.Match.Path != "/admin" || item.Match.PathMatch != "prefix" || item.Priority != 80 {
		t.Fatalf("unexpected access control match: %+v", item)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/access-control/rules/"+strconv.FormatInt(item.ID, 10), nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get access control status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAccessControlRuleWriteLifecycleAndAudit(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	body := bytes.NewBufferString(`{"name":"Trusted source","site_id":3,"priority":50,"match":{"target":"cidr","value":"10.0.0.0/8"},"action":{"type":"allow"}}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/access-control/rules", body), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create access control status = %d body=%s", rec.Code, rec.Body.String())
	}
	var createResponse struct {
		Item model.ProtectionRule `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&createResponse); err != nil {
		t.Fatalf("decode create access control: %v", err)
	}
	if createResponse.Item.Match.Target != "cidr" || createResponse.Item.Action.Type != "allow" || createResponse.Item.Priority != 50 {
		t.Fatalf("unexpected created access control: %+v", createResponse.Item)
	}

	updateBody := bytes.NewBufferString(`{"name":"Header observe","site_id":3,"enabled":false,"match":{"target":"header","header_name":"X-Forwarded-For","value":"proxy","operator":"contains"},"action":{"type":"log-only"}}`)
	req = withToken(httptest.NewRequest(http.MethodPut, "/api/v1/access-control/rules/"+strconv.FormatInt(createResponse.Item.ID, 10), updateBody), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update access control status = %d body=%s", rec.Code, rec.Body.String())
	}
	var updateResponse struct {
		Item model.ProtectionRule `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&updateResponse); err != nil {
		t.Fatalf("decode update access control: %v", err)
	}
	if updateResponse.Item.Enabled || updateResponse.Item.Match.Target != "header" || updateResponse.Item.Action.Type != "log-only" {
		t.Fatalf("unexpected updated access control: %+v", updateResponse.Item)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs?resource_type=access_control_rule", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit list status = %d body=%s", rec.Code, rec.Body.String())
	}
	var auditResponse struct {
		Items []model.AuditLog `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&auditResponse); err != nil {
		t.Fatalf("decode audit logs: %v", err)
	}
	if len(auditResponse.Items) < 2 {
		t.Fatalf("expected create and update audit logs, got %+v", auditResponse.Items)
	}

	req = withToken(httptest.NewRequest(http.MethodDelete, "/api/v1/access-control/rules/"+strconv.FormatInt(createResponse.Item.ID, 10), nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete access control status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAccessControlWriteValidationAndAuthorization(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	invalidBodies := []string{
		`{"name":"bad","match":{"target":"ip","value":"999.1.1.1"},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"target":"cidr","value":"10.0.0.0"},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"target":"path","path":"admin","path_match":"prefix"},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"target":"path","path":"/admin","path_match":"regex"},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"target":"header","value":"bot","operator":"contains"},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"target":"host","host":"example.com","operator":"contains"},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"target":"host","host":"example.com","operator":"exact"},"action":{"type":"challenge"}}`,
		`{"name":"bad","priority":-1,"match":{"target":"host","host":"example.com","operator":"exact"},"action":{"type":"block"}}`,
	}
	for _, body := range invalidBodies {
		req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/access-control/rules", bytes.NewBufferString(body)), token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %s status = %d body=%s", body, rec.Code, rec.Body.String())
		}
	}

	readonlyToken, _, err := auth.IssueToken("test-secret", "readonly", 99, "readonly", 3600000000000)
	if err != nil {
		t.Fatalf("issue readonly token: %v", err)
	}
	validBody := bytes.NewBufferString(`{"name":"Admin path","match":{"target":"path","path":"/admin","path_match":"prefix"},"action":{"type":"block"}}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/access-control/rules", validBody), readonlyToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly create status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCCProtectionRulesMapRateLimits(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	body := bytes.NewBufferString(`{"name":"Login brute force","scope":"uri","match_value":"/api/login","threshold":10,"window_sec":60,"action":"block","ban_duration_sec":600,"site_id":7}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rate-limits", body), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create rate limit status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/cc-protection/rules?site_id=7&enabled=true", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list cc protection status = %d body=%s", rec.Code, rec.Body.String())
	}
	var listResponse struct {
		Items []model.ProtectionRule `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&listResponse); err != nil {
		t.Fatalf("decode cc protection list: %v", err)
	}
	if len(listResponse.Items) != 1 {
		t.Fatalf("expected 1 cc protection rule, got %+v", listResponse.Items)
	}
	item := listResponse.Items[0]
	if item.Module != "cc-protection" || item.Category != "rate-limit" {
		t.Fatalf("unexpected module/category: %+v", item)
	}
	if item.Match.Path != "/api/login" || item.Match.PathMatch != "exact" || len(item.Match.Methods) != 0 {
		t.Fatalf("unexpected match mapping: %+v", item.Match)
	}
	if item.Limit.Counter != "client_ip_path" || item.Limit.Threshold != 10 || item.Limit.WindowSec != 60 || item.Limit.BanDurationSec != 600 {
		t.Fatalf("unexpected limit mapping: %+v", item.Limit)
	}
	if item.Action.Type != "block" || item.Priority != 100 || item.SiteID != 7 || !item.Enabled {
		t.Fatalf("unexpected action or metadata mapping: %+v", item)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/cc-protection/rules/"+strconv.FormatInt(item.ID, 10), nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get cc protection status = %d body=%s", rec.Code, rec.Body.String())
	}
	var getResponse struct {
		Item model.ProtectionRule `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&getResponse); err != nil {
		t.Fatalf("decode cc protection item: %v", err)
	}
	if getResponse.Item.ID != item.ID || getResponse.Item.Module != "cc-protection" {
		t.Fatalf("unexpected cc protection item: %+v", getResponse.Item)
	}
}

func TestCCProtectionRulesFilterValidation(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	for _, path := range []string{
		"/api/v1/cc-protection/rules?site_id=-1",
		"/api/v1/cc-protection/rules?enabled=yes",
	} {
		req := withToken(httptest.NewRequest(http.MethodGet, path, nil), token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d body=%s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestCCProtectionRuleWriteLifecycleAndAudit(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	body := bytes.NewBufferString(`{"name":"API limit","site_id":3,"match":{"path":"/api/","path_match":"prefix","methods":["get","POST"]},"limit":{"counter":"client_ip_path","threshold":120,"window_sec":60,"ban_duration_sec":60},"action":{"type":"rate-limit"}}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/cc-protection/rules", body), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create cc protection status = %d body=%s", rec.Code, rec.Body.String())
	}
	var createResponse struct {
		Item model.ProtectionRule `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&createResponse); err != nil {
		t.Fatalf("decode create cc protection: %v", err)
	}
	if createResponse.Item.Match.PathMatch != "prefix" || len(createResponse.Item.Match.Methods) != 2 || createResponse.Item.Limit.Counter != "client_ip_path" {
		t.Fatalf("unexpected created cc protection mapping: %+v", createResponse.Item)
	}
	if createResponse.Item.Action.Type != "rate-limit" {
		t.Fatalf("expected user-facing action mapping to rate-limit, got %+v", createResponse.Item.Action)
	}
	if createResponse.Item.Source != "protection_rules" || createResponse.Item.MigrationStatus != "native" {
		t.Fatalf("expected native protection rule metadata, got %+v", createResponse.Item)
	}

	listReq := withToken(httptest.NewRequest(http.MethodGet, "/api/v1/cc-protection/rules", nil), token)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list native cc protection status = %d body=%s", listRec.Code, listRec.Body.String())
	}
	var nativeList struct {
		Items []model.ProtectionRule `json:"items"`
	}
	if err := json.NewDecoder(listRec.Body).Decode(&nativeList); err != nil {
		t.Fatalf("decode native cc list: %v", err)
	}
	if len(nativeList.Items) != 1 || nativeList.Items[0].ID != createResponse.Item.ID || nativeList.Items[0].Source != "protection_rules" {
		t.Fatalf("expected list to prefer native protection rule, got %+v", nativeList.Items)
	}

	updateBody := bytes.NewBufferString(`{"name":"Login ban","site_id":3,"enabled":false,"match":{"path":"/api/login","path_match":"exact","methods":["POST"]},"limit":{"counter":"client_ip","threshold":10,"window_sec":60,"ban_duration_sec":600},"action":{"type":"ban"}}`)
	req = withToken(httptest.NewRequest(http.MethodPut, "/api/v1/cc-protection/rules/"+strconv.FormatInt(createResponse.Item.ID, 10), updateBody), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update cc protection status = %d body=%s", rec.Code, rec.Body.String())
	}
	var updateResponse struct {
		Item model.ProtectionRule `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&updateResponse); err != nil {
		t.Fatalf("decode update cc protection: %v", err)
	}
	if updateResponse.Item.Enabled || updateResponse.Item.Match.Path != "/api/login" || updateResponse.Item.Limit.Counter != "client_ip" {
		t.Fatalf("unexpected updated cc protection: %+v", updateResponse.Item)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs?resource_type=cc_protection_rule", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit list status = %d body=%s", rec.Code, rec.Body.String())
	}
	var auditResponse struct {
		Items []model.AuditLog `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&auditResponse); err != nil {
		t.Fatalf("decode audit logs: %v", err)
	}
	if len(auditResponse.Items) < 2 {
		t.Fatalf("expected create and update audit logs, got %+v", auditResponse.Items)
	}

	req = withToken(httptest.NewRequest(http.MethodDelete, "/api/v1/cc-protection/rules/"+strconv.FormatInt(createResponse.Item.ID, 10), nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete cc protection status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestProtectionOverviewAndPublishPreviewModuleMatrix(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	rateLimitBody := bytes.NewBufferString(`{"name":"全站低阈值","scope":"site","match_value":"/","path_match":"prefix","threshold":10,"window_sec":60,"action":"block","ban_duration_sec":300,"site_id":1,"enabled":true}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rate-limits", rateLimitBody), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create rate limit status = %d body=%s", rec.Code, rec.Body.String())
	}

	accessBody := bytes.NewBufferString(`{"name":"全站放行","kind":"whitelist","target":"uri","value":"/","match_operator":"prefix","action":"allow","site_id":1,"enabled":true,"priority":10}`)
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/access-lists", accessBody), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create access list status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/protection/overview", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("overview status = %d body=%s", rec.Code, rec.Body.String())
	}
	var overviewResponse struct {
		Item model.ProtectionOverview `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&overviewResponse); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	var ccModule, accessModule model.ProtectionModuleOverview
	for _, module := range overviewResponse.Item.Modules {
		switch module.Key {
		case "cc-protection":
			ccModule = module
		case "access-control":
			accessModule = module
		}
	}
	if ccModule.CompatibilitySource != "rate_limits" || ccModule.Enabled != 1 || len(ccModule.Warnings) == 0 {
		t.Fatalf("unexpected cc overview: %+v", ccModule)
	}
	if accessModule.CompatibilitySource != "access_lists" || accessModule.Allow != 1 || len(accessModule.Warnings) == 0 {
		t.Fatalf("unexpected access overview: %+v", accessModule)
	}
	if len(overviewResponse.Item.Risks) < 2 {
		t.Fatalf("expected module risks, got %+v", overviewResponse.Item.Risks)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/releases/preview", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview status = %d body=%s", rec.Code, rec.Body.String())
	}
	var preview map[string]map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&preview); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	summary := preview["summary"]
	if summary["module_matrix"] == nil || summary["risk_warnings"] == nil {
		t.Fatalf("preview missing module matrix or risks: %+v", summary)
	}
	if int(summary["rate_limits"].(float64)) != 1 || int(summary["access_lists"].(float64)) != 1 {
		t.Fatalf("preview lost compatibility counts: %+v", summary)
	}
	if summary["compatibility_diagnostics"] == nil {
		t.Fatalf("preview missing compatibility diagnostics: %+v", summary)
	}
}

func TestProtectionMigrationHealthEndpointEmptyAndAuth(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/protection/migration-health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/protection/migration-health", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Item model.ProtectionRuleMigrationHealth `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if response.Item.ProtectionRules.Total != 0 || len(response.Item.Issues) != 0 {
		t.Fatalf("empty health fabricated data: %+v", response.Item)
	}
	if response.Item.Backfill.Status != "healthy" {
		t.Fatalf("empty health should be healthy, got %+v", response.Item.Backfill)
	}
}

func TestProtectionMigrationHealthDetectsLegacyCoverage(t *testing.T) {
	legacy := model.RateLimitRule{
		ID:         10,
		Name:       "Login limit",
		Scope:      "uri",
		MatchValue: "/api/login",
		PathMatch:  "exact",
		Threshold:  10,
		WindowSec:  60,
		Action:     "block",
		SiteID:     1,
		Enabled:    true,
	}
	candidate := legacyProtectionCandidate{
		Store:    "rate_limits",
		Module:   "cc-protection",
		Category: "rate-limit",
		Ref:      "rate_limits:10",
		Rule:     publish.CCProtectionFromRateLimit(legacy),
	}

	health := buildProtectionRuleMigrationHealth(nil, []legacyProtectionCandidate{candidate})
	if len(health.Issues) != 1 || health.Issues[0].Type != "missing_migration" {
		t.Fatalf("expected missing migration issue, got %+v", health.Issues)
	}
	if len(health.LegacyStores) != 1 || health.LegacyStores[0].Missing != 1 || health.Backfill.Status != "attention_required" {
		t.Fatalf("unexpected missing health state: %+v", health)
	}

	migrated := candidate.Rule
	migrated.ID = 100
	migrated.Source = "legacy"
	migrated.MigrationStatus = "migrated"
	health = buildProtectionRuleMigrationHealth([]model.ProtectionRule{migrated}, []legacyProtectionCandidate{candidate})
	if len(health.Issues) != 0 || health.LegacyStores[0].Migrated != 1 {
		t.Fatalf("expected migrated health without issues, got %+v", health)
	}

	duplicate := migrated
	duplicate.ID = 101
	health = buildProtectionRuleMigrationHealth([]model.ProtectionRule{migrated, duplicate}, []legacyProtectionCandidate{candidate})
	if len(health.Issues) == 0 || health.LegacyStores[0].Duplicates == 0 {
		t.Fatalf("expected duplicate legacy_ref issue, got %+v", health)
	}

	conflict := migrated
	conflict.ID = 102
	conflict.Limit.Threshold = 20
	health = buildProtectionRuleMigrationHealth([]model.ProtectionRule{conflict}, []legacyProtectionCandidate{candidate})
	if len(health.Issues) == 0 || health.LegacyStores[0].Conflicts != 1 {
		t.Fatalf("expected migration conflict issue, got %+v", health)
	}

	orphan := migrated
	orphan.LegacyRef = "rate_limits:404"
	health = buildProtectionRuleMigrationHealth([]model.ProtectionRule{orphan}, []legacyProtectionCandidate{candidate})
	if len(health.Issues) < 2 || health.LegacyStores[0].Orphaned != 1 {
		t.Fatalf("expected missing plus orphan issues, got %+v", health)
	}
}

func TestCCProtectionWriteValidationAndAuthorization(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	invalidBodies := []string{
		`{"name":"bad","match":{"path":"api","path_match":"exact"},"limit":{"counter":"client_ip","threshold":1,"window_sec":1},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"path":"/api","path_match":"regex"},"limit":{"counter":"client_ip","threshold":1,"window_sec":1},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"path":"/api","path_match":"exact","methods":["TRACE"]},"limit":{"counter":"client_ip","threshold":1,"window_sec":1},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"path":"/api","path_match":"exact"},"limit":{"counter":"cookie","threshold":1,"window_sec":1},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"path":"/api","path_match":"exact"},"limit":{"counter":"client_ip","threshold":0,"window_sec":1},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"path":"/api","path_match":"exact"},"limit":{"counter":"client_ip","threshold":1,"window_sec":0},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"path":"/api","path_match":"exact"},"limit":{"counter":"client_ip","threshold":1,"window_sec":1,"ban_duration_sec":-1},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"path":"/api","path_match":"exact"},"limit":{"counter":"client_ip","threshold":1,"window_sec":1},"action":{"type":"challenge"}}`,
	}
	for _, body := range invalidBodies {
		req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/cc-protection/rules", bytes.NewBufferString(body)), token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %s status = %d body=%s", body, rec.Code, rec.Body.String())
		}
	}

	readonlyToken, _, err := auth.IssueToken("test-secret", "readonly", 99, "readonly", 3600000000000)
	if err != nil {
		t.Fatalf("issue readonly token: %v", err)
	}
	validBody := bytes.NewBufferString(`{"name":"API limit","match":{"path":"/api/","path_match":"prefix"},"limit":{"counter":"client_ip_path","threshold":120,"window_sec":60},"action":{"type":"rate-limit"}}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/cc-protection/rules", validBody), readonlyToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly create status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAttackProtectionGroupsLifecycleAndAudit(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	req := withToken(httptest.NewRequest(http.MethodGet, "/api/v1/attack-protection/groups", nil), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list attack protection status = %d body=%s", rec.Code, rec.Body.String())
	}
	var listResponse struct {
		Items []model.AttackProtectionGroup `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&listResponse); err != nil {
		t.Fatalf("decode attack protection list: %v", err)
	}
	if len(listResponse.Items) != 4 {
		t.Fatalf("expected 4 managed attack groups, got %+v", listResponse.Items)
	}
	foundTraversal := false
	for _, item := range listResponse.Items {
		if item.Module != "attack-protection" || item.Category != "managed" || item.RuleCount == 0 {
			t.Fatalf("unexpected attack protection group: %+v", item)
		}
		if item.AttackType == "path-traversal" {
			foundTraversal = true
		}
	}
	if !foundTraversal {
		t.Fatalf("expected path traversal group, got %+v", listResponse.Items)
	}

	body := bytes.NewBufferString(`{"enabled":false,"action":"log-only","priority":42}`)
	req = withToken(httptest.NewRequest(http.MethodPut, "/api/v1/attack-protection/groups/sqli", body), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update attack protection status = %d body=%s", rec.Code, rec.Body.String())
	}
	var updateResponse struct {
		Item model.AttackProtectionGroup `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&updateResponse); err != nil {
		t.Fatalf("decode attack protection update: %v", err)
	}
	if updateResponse.Item.AttackType != "sqli" || updateResponse.Item.Enabled || updateResponse.Item.Action != "log-only" || updateResponse.Item.Priority != 42 {
		t.Fatalf("unexpected updated attack protection group: %+v", updateResponse.Item)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs?resource_type=attack_protection_group", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit list status = %d body=%s", rec.Code, rec.Body.String())
	}
	var auditResponse struct {
		Items []model.AuditLog `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&auditResponse); err != nil {
		t.Fatalf("decode attack protection audits: %v", err)
	}
	if len(auditResponse.Items) == 0 || auditResponse.Items[0].Action != "update" {
		t.Fatalf("expected attack protection audit, got %+v", auditResponse.Items)
	}
}

func TestAttackProtectionValidationAndAuthorization(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	invalidBodies := map[string]string{
		"/api/v1/attack-protection/groups/unknown":  `{"action":"block","priority":10}`,
		"/api/v1/attack-protection/groups/sqli":     `{"action":"challenge","priority":10}`,
		"/api/v1/attack-protection/groups/sqli?x=1": `{"action":"block","priority":0}`,
	}
	for path, body := range invalidBodies {
		req := withToken(httptest.NewRequest(http.MethodPut, path, bytes.NewBufferString(body)), token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d body=%s", path, rec.Code, rec.Body.String())
		}
	}

	readonlyToken, _, err := auth.IssueToken("test-secret", "readonly", 99, "readonly", 3600000000000)
	if err != nil {
		t.Fatalf("issue readonly token: %v", err)
	}
	req := withToken(httptest.NewRequest(http.MethodGet, "/api/v1/attack-protection/groups", nil), readonlyToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("readonly list status = %d body=%s", rec.Code, rec.Body.String())
	}
	req = withToken(httptest.NewRequest(http.MethodPut, "/api/v1/attack-protection/groups/sqli", bytes.NewBufferString(`{"action":"block","priority":10}`)), readonlyToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly update status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRuleCommunityCatalogTrustExportAndAuthorization(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)
	packageBody := `{"id":"community-pack","name":"community-pack","version":"v1","author":"LiteWaf","license":"MIT","compatibility":"litewaf-rule-package-v1","defaults":{"enabled":false,"review_status":"pending-review"},"rules":[{"id":"xss-query","name":"Community XSS","type":"xss","target":"args","action":"block","expression":"(?i)<script","score":80}]}`
	catalog := map[string]any{
		"schema_version": "litewaf-rule-catalog-v1",
		"packages": []map[string]any{
			{"id": "community-pack", "name": "Community Pack", "version": "v1", "compatibility": "litewaf-rule-package-v1", "package": json.RawMessage(packageBody)},
		},
	}
	data, err := json.Marshal(catalog)
	if err != nil {
		t.Fatalf("marshal catalog: %v", err)
	}
	catalogPath := t.TempDir() + "/catalog.json"
	if err := os.WriteFile(catalogPath, data, 0o644); err != nil {
		t.Fatalf("write catalog: %v", err)
	}

	body := bytes.NewBufferString(`{"name":"Local catalog","source":` + strconv.Quote(catalogPath) + `,"enabled":true,"timeout_sec":5}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/catalogs", body), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create catalog status = %d body=%s", rec.Code, rec.Body.String())
	}
	var catalogResponse struct {
		Item model.RuleCatalogSource `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&catalogResponse); err != nil {
		t.Fatalf("decode catalog: %v", err)
	}

	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/catalogs/"+strconv.FormatInt(catalogResponse.Item.ID, 10)+"/sync", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sync catalog status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/catalogs/"+strconv.FormatInt(catalogResponse.Item.ID, 10)+"/packages/community-pack/preview", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview remote status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/catalogs/"+strconv.FormatInt(catalogResponse.Item.ID, 10)+"/packages/community-pack/apply-update", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("apply update status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/trust-keys", bytes.NewBufferString(`{"key_id":"community-key","algorithm":"local","owner":"Community","public_key":"public","enabled":true}`)), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create trust key status = %d body=%s", rec.Code, rec.Body.String())
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("public_key")) {
		t.Fatalf("trust key response leaked public key payload: %s", rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list rules status = %d body=%s", rec.Code, rec.Body.String())
	}
	var rulesResponse struct {
		Items []model.Rule `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&rulesResponse); err != nil {
		t.Fatalf("decode rules: %v", err)
	}
	var importedID int64
	for _, rule := range rulesResponse.Items {
		if rule.PackageID == "community-pack" {
			importedID = rule.ID
		}
	}
	if importedID == 0 {
		t.Fatalf("expected imported rule, got %+v", rulesResponse.Items)
	}
	exportBody := bytes.NewBufferString(`{"package_id":"exported-pack","name":"Exported Pack","version":"v1","author":"LiteWaf","license":"MIT","rule_ids":[` + strconv.FormatInt(importedID, 10) + `]}`)
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/export/preview", exportBody), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("export preview status = %d body=%s", rec.Code, rec.Body.String())
	}

	readonlyToken, _, err := auth.IssueToken("test-secret", "readonly", 99, "readonly", 3600000000000)
	if err != nil {
		t.Fatalf("issue readonly token: %v", err)
	}
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/catalogs", bytes.NewBufferString(`{"name":"x","source":"https://example.com/catalog.json"}`)), readonlyToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly create catalog status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRuleCommunityPhaseTwoAccountsQueueFeedbackAndRedaction(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	accountBody := `{"name":"Paid feed","provider_type":"https-catalog","endpoint":"https://rules.example.com/catalog.json","enabled":true,"timeout_sec":5,"credential":{"alias":"prod"},"credential_secret":"super-secret-token"}`
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/account-sources", bytes.NewBufferString(accountBody)), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create account source status = %d body=%s", rec.Code, rec.Body.String())
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("super-secret-token")) || bytes.Contains(rec.Body.Bytes(), []byte("credential_secret")) {
		t.Fatalf("account source response leaked secret: %s", rec.Body.String())
	}
	var accountResponse struct {
		Item model.RuleCommunityAccountSource `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&accountResponse); err != nil {
		t.Fatalf("decode account source: %v", err)
	}
	if accountResponse.Item.Credential.LastFour != "oken" || accountResponse.Item.Credential.Status != "configured" {
		t.Fatalf("expected redacted credential metadata, got %+v", accountResponse.Item.Credential)
	}

	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/account-sources/"+strconv.FormatInt(accountResponse.Item.ID, 10)+"/refresh", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh account source status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/rule-community/review-queue", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list queue status = %d body=%s", rec.Code, rec.Body.String())
	}
	var queueResponse struct {
		Items []model.RuleReviewQueueItem `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&queueResponse); err != nil {
		t.Fatalf("decode queue: %v", err)
	}
	if len(queueResponse.Items) != 1 || queueResponse.Items[0].State != "queued" {
		t.Fatalf("expected queued recommendation, got %+v", queueResponse.Items)
	}

	req = withToken(httptest.NewRequest(http.MethodPut, "/api/v1/rule-community/review-queue/"+strconv.FormatInt(queueResponse.Items[0].ID, 10), bytes.NewBufferString(`{"state":"dismissed","reason":"not needed"}`)), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dismiss queue status = %d body=%s", rec.Code, rec.Body.String())
	}

	ruleBody := `{"name":"Feedback XSS","type":"xss","target":"args","action":"block","expression":"(?i)<script","score":80,"enabled":true,"module":"attack-protection","category":"managed","attack_type":"xss","group":"XSS 防护","priority":100}`
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewBufferString(ruleBody)), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create feedback rule status = %d body=%s", rec.Code, rec.Body.String())
	}
	var ruleResponse struct {
		Item model.Rule `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&ruleResponse); err != nil {
		t.Fatalf("decode feedback rule: %v", err)
	}
	rule := ruleResponse.Item
	feedbackBody := `{"rule_id":` + strconv.FormatInt(rule.ID, 10) + `,"reason":"false positive on encoded sample","severity":"medium","redacted_sample":{"path":"/search","body":"[redacted]"}}`
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/feedback", bytes.NewBufferString(feedbackBody)), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create feedback status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/rule-community/feedback-suggestions", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list suggestions status = %d body=%s", rec.Code, rec.Body.String())
	}
	var suggestionsResponse struct {
		Items []model.RuleFeedbackSuggestion `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&suggestionsResponse); err != nil {
		t.Fatalf("decode suggestions: %v", err)
	}
	if len(suggestionsResponse.Items) != 1 || suggestionsResponse.Items[0].State != "queued" {
		t.Fatalf("expected queued suggestion, got %+v", suggestionsResponse.Items)
	}

	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/feedback-suggestions/"+strconv.FormatInt(suggestionsResponse.Items[0].ID, 10)+"/test", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("test suggestion status = %d body=%s", rec.Code, rec.Body.String())
	}

	targetBody := `{"name":"Community Git","provider":"https","endpoint":"https://community.example.com/push","channel":"main","enabled":true,"credential":{"alias":"push"},"credential_secret":"push-secret"}`
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/contribution-targets", bytes.NewBufferString(targetBody)), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create target status = %d body=%s", rec.Code, rec.Body.String())
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("push-secret")) {
		t.Fatalf("target response leaked secret: %s", rec.Body.String())
	}
	var targetResponse struct {
		Item model.RuleContributionTarget `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&targetResponse); err != nil {
		t.Fatalf("decode target: %v", err)
	}
	pushBody := `{"target_id":` + strconv.FormatInt(targetResponse.Item.ID, 10) + `,"artifact":{"package":{"id":"exported-pack","name":"Exported","version":"v1","compatibility":"litewaf-rule-package-v1","signature_status":"unsigned"},"artifact":"{\"id\":\"exported-pack\"}","checksum":"abc","rule_count":1}}`
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/contribution-pushes/preview", bytes.NewBufferString(pushBody)), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview push status = %d body=%s", rec.Code, rec.Body.String())
	}
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/contribution-pushes", bytes.NewBufferString(pushBody)), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("execute push status = %d body=%s", rec.Code, rec.Body.String())
	}

	readonlyToken, _, err := auth.IssueToken("test-secret", "readonly", 99, "readonly", 3600000000000)
	if err != nil {
		t.Fatalf("issue readonly token: %v", err)
	}
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/account-sources", bytes.NewBufferString(accountBody)), readonlyToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly create account source status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAttackProtectionEventQueryAndSummary(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/waf-events", bytes.NewBufferString(`{"request_id":"req-attack","site_id":1,"event_type":"rule","rule_id":1,"rule_type":"sqli","target":"args","module":"attack-protection","category":"managed","attack_type":"sqli","group_name":"SQL 注入防护","rule_name":"LiteWaf SQLi baseline","action":"block","disposition":"blocked","client_ip":"192.0.2.30","method":"GET","uri":"/search?q=1","summary":"bounded match","score":80}`))
	req.Header.Set("Authorization", "Bearer gateway-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("ingest attack protection waf status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/attack-logs?module=attack-protection&attack_type=sqli", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("query attack protection logs status = %d body=%s", rec.Code, rec.Body.String())
	}
	var attackResponse struct {
		Items []model.WAFEvent `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&attackResponse); err != nil {
		t.Fatalf("decode attack protection logs: %v", err)
	}
	if len(attackResponse.Items) != 1 || attackResponse.Items[0].AttackType != "sqli" || attackResponse.Items[0].GroupName == "" {
		t.Fatalf("unexpected attack protection logs: %+v", attackResponse.Items)
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
	if len(summaryResponse.Item.AttackProtection) != 1 || summaryResponse.Item.AttackProtection[0].Key != "sqli|block|blocked" {
		t.Fatalf("unexpected attack protection summary: %+v", summaryResponse.Item)
	}
}

func TestUploadProtectionEventQueryAndSummary(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/waf-events", bytes.NewBufferString(`{"request_id":"req-upload","site_id":1,"event_type":"upload-protection","rule_id":9,"rule_type":"upload","target":"upload_extension","module":"upload-protection","category":"upload","rule_name":"Script upload block","action":"block","disposition":"blocked","client_ip":"192.0.2.40","method":"POST","uri":"/upload","summary":"extension php blocked","threshold":1048576,"upload_metadata":"filename=shell.php, extension=php, content_length=2048"}`))
	req.Header.Set("Authorization", "Bearer gateway-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("ingest upload protection waf status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/attack-logs?module=upload-protection&action=block", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("query upload protection logs status = %d body=%s", rec.Code, rec.Body.String())
	}
	var attackResponse struct {
		Items []model.WAFEvent `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&attackResponse); err != nil {
		t.Fatalf("decode upload protection logs: %v", err)
	}
	if len(attackResponse.Items) != 1 || attackResponse.Items[0].Module != "upload-protection" || attackResponse.Items[0].UploadMetadata == "" {
		t.Fatalf("unexpected upload protection logs: %+v", attackResponse.Items)
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
	if len(summaryResponse.Item.UploadProtection) != 1 || summaryResponse.Item.UploadProtection[0].Key != "block|blocked" {
		t.Fatalf("unexpected upload protection summary: %+v", summaryResponse.Item)
	}
}

func TestBotProtectionEventQueryAndSummary(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/waf-events", bytes.NewBufferString(`{"request_id":"req-bot","site_id":1,"event_type":"bot-protection","rule_id":11,"rule_type":"challenge","target":"path","module":"bot-protection","category":"challenge","rule_name":"Admin challenge","challenge_mode":"js-challenge","challenge_result":"failed","action":"block","disposition":"blocked","client_ip":"192.0.2.50","method":"GET","uri":"/admin","summary":"challenge failed"}`))
	req.Header.Set("Authorization", "Bearer gateway-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("ingest bot protection waf status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/attack-logs?module=bot-protection&challenge_result=failed", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("query bot protection logs status = %d body=%s", rec.Code, rec.Body.String())
	}
	var attackResponse struct {
		Items []model.WAFEvent `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&attackResponse); err != nil {
		t.Fatalf("decode bot protection logs: %v", err)
	}
	if len(attackResponse.Items) != 1 || attackResponse.Items[0].Module != "bot-protection" || attackResponse.Items[0].ChallengeResult != "failed" {
		t.Fatalf("unexpected bot protection logs: %+v", attackResponse.Items)
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
	if len(summaryResponse.Item.BotProtection) != 1 || summaryResponse.Item.BotProtection[0].Key != "failed|block|blocked" {
		t.Fatalf("unexpected bot protection summary: %+v", summaryResponse.Item)
	}
}

func TestDynamicProtectionEventQueryAndSummary(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/waf-events", bytes.NewBufferString(`{"request_id":"req-dynamic","site_id":1,"event_type":"dynamic-protection","rule_id":15,"rule_type":"dynamic-token","target":"path","module":"dynamic-protection","category":"dynamic-token","rule_name":"Admin token","advanced_target":"token-failed","action":"block","disposition":"blocked","client_ip":"192.0.2.60","method":"GET","uri":"/admin","summary":"dynamic token failed"}`))
	req.Header.Set("Authorization", "Bearer gateway-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("ingest dynamic protection waf status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/attack-logs?module=dynamic-protection&dynamic_result=token-failed", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("query dynamic protection logs status = %d body=%s", rec.Code, rec.Body.String())
	}
	var attackResponse struct {
		Items []model.WAFEvent `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&attackResponse); err != nil {
		t.Fatalf("decode dynamic protection logs: %v", err)
	}
	if len(attackResponse.Items) != 1 || attackResponse.Items[0].Module != "dynamic-protection" || attackResponse.Items[0].AdvancedTarget != "token-failed" {
		t.Fatalf("unexpected dynamic protection logs: %+v", attackResponse.Items)
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
	if len(summaryResponse.Item.DynamicProtection) != 1 || summaryResponse.Item.DynamicProtection[0].Key != "dynamic-token|token-failed|block|blocked" {
		t.Fatalf("unexpected dynamic protection summary: %+v", summaryResponse.Item)
	}
}
