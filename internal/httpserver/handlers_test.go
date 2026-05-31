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
