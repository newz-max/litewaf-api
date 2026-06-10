package httpserver

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

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

func writeTestGeoIPDatabase(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "geoip.csv")
	data := "cidr,country_code,country,region,city,district,longitude,latitude,source,version\n" +
		"8.8.8.0/24,CN,中国,北京,北京,朝阳区,116.4,39.9,test-db,2026\n" +
		"1.1.1.0/24,SG,新加坡,,,,103.8,1.3,test-db,2026\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write test geoip database: %v", err)
	}
	return path
}

func testServerWithConfig(t *testing.T, configure func(*config.Config)) http.Handler {
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
	if configure != nil {
		configure(&cfg)
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

func TestApplicationCRUD(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	body := bytes.NewBufferString(`{"name":"Example","mode":"protect","hosts":[{"host":"example.test","is_primary":true}],"listeners":[{"port":80,"protocol":"http","enabled":true}],"upstreams":[{"name":"primary","url":"http://upstream:8080","weight":1,"enabled":true}]}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/applications", body), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil), token)
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
		t.Fatalf("expected 1 application, got %d", len(response.Items))
	}
}

func TestCreateApplicationValidation(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)
	body := bytes.NewBufferString(`{"name":"Bad","mode":"protect","hosts":[],"listeners":[{"port":443,"protocol":"https","enabled":true}],"upstreams":[{"url":"nope","enabled":true}]}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/applications", body), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestNotFound(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)
	req := withToken(httptest.NewRequest(http.MethodGet, "/api/v1/applications/404", nil), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestProtectedEndpointRequiresToken(t *testing.T) {
	handler := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestEmptyListsReturnArrays(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	for _, path := range []string{"/api/v1/applications", "/api/v1/certificates"} {
		req := withToken(httptest.NewRequest(http.MethodGet, path, nil), token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d body=%s", path, rec.Code, rec.Body.String())
		}

		var response map[string]json.RawMessage
		if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
			t.Fatalf("%s decode: %v", path, err)
		}
		if string(response["items"]) != "[]" {
			t.Fatalf("%s expected items to be [], got %s", path, response["items"])
		}
	}
}

func TestSitesRouteRemoved(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)
	req := withToken(httptest.NewRequest(http.MethodGet, "/api/v1/sites", nil), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected removed sites route to return 404, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCertificateUploadRedactsPrivateKey(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)
	certPEM, keyPEM := testHTTPServerCertificatePEM(t, "app.example.test")
	payload, _ := json.Marshal(map[string]string{
		"name":     "App cert",
		"cert_pem": certPEM,
		"key_pem":  keyPEM,
	})
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/certificates", bytes.NewReader(payload)), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload status = %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatalf("certificate response leaked private key: %s", rec.Body.String())
	}
	assertNoCertificateMaterial(t, rec.Body.String(), certPEM, keyPEM)

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatalf("certificate list leaked private key: %s", rec.Body.String())
	}
	assertNoCertificateMaterial(t, rec.Body.String(), certPEM, keyPEM)

	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/certificates/validate", bytes.NewReader(payload)), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("validate status = %d body=%s", rec.Code, rec.Body.String())
	}
	assertNoCertificateMaterial(t, rec.Body.String(), certPEM, keyPEM)

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs?resource_type=certificate", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit status = %d body=%s", rec.Code, rec.Body.String())
	}
	assertNoCertificateMaterial(t, rec.Body.String(), certPEM, keyPEM)
	var auditResponse struct {
		Items []model.AuditLog `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&auditResponse); err != nil {
		t.Fatalf("decode certificate audit: %v", err)
	}
	if len(auditResponse.Items) < 2 {
		t.Fatalf("expected upload and validate certificate audit entries: %+v", auditResponse.Items)
	}
	hasValidate := false
	for _, item := range auditResponse.Items {
		if item.Action == "validate" {
			hasValidate = true
		}
	}
	if !hasValidate {
		t.Fatalf("expected certificate validate audit entry: %+v", auditResponse.Items)
	}
}

func TestPublishPreviewSummarizesApplicationsAndCertificateRisks(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)
	certPEM, keyPEM := testHTTPServerCertificatePEM(t, "other.example.test")
	certPayload, _ := json.Marshal(map[string]string{
		"name":     "Other cert",
		"cert_pem": certPEM,
		"key_pem":  keyPEM,
	})
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/certificates", bytes.NewReader(certPayload)), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload cert status = %d body=%s", rec.Code, rec.Body.String())
	}
	var certResponse struct {
		Item model.Certificate `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&certResponse); err != nil {
		t.Fatalf("decode cert: %v", err)
	}

	appPayload, _ := json.Marshal(map[string]any{
		"name":    "Example",
		"mode":    "protect",
		"enabled": true,
		"hosts": []map[string]any{
			{"host": "app.example.test", "is_primary": true},
		},
		"listeners": []map[string]any{
			{"port": 80, "protocol": "http", "enabled": true},
			{"port": 443, "protocol": "https", "certificate_id": certResponse.Item.ID, "enabled": true},
		},
		"upstreams": []map[string]any{
			{"name": "primary", "url": "http://upstream:8080", "weight": 1, "enabled": true},
		},
	})
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/applications", bytes.NewReader(appPayload)), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create app status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/releases/preview", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Summary map[string]any `json:"summary"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if int(response.Summary["applications"].(float64)) != 1 ||
		int(response.Summary["application_hosts"].(float64)) != 1 ||
		int(response.Summary["application_listeners"].(float64)) != 2 ||
		int(response.Summary["https_listeners"].(float64)) != 1 ||
		int(response.Summary["certificates"].(float64)) != 1 ||
		int(response.Summary["enabled_upstreams"].(float64)) != 1 {
		t.Fatalf("unexpected application preview summary: %+v", response.Summary)
	}
	if _, ok := response.Summary["sites"]; ok {
		t.Fatalf("preview must not expose legacy sites count: %+v", response.Summary)
	}
	validation, ok := response.Summary["application_validation"].(map[string]any)
	if !ok || int(validation["warnings"].(float64)) != 1 {
		t.Fatalf("expected certificate-domain warning: %+v", response.Summary)
	}
	issues, ok := validation["issues"].([]any)
	if !ok || len(issues) != 1 {
		t.Fatalf("expected one validation issue: %+v", validation)
	}
	issue, ok := issues[0].(map[string]any)
	if !ok || issue["category"] != "certificate-domain-mismatch" || issue["severity"] != "warning" {
		t.Fatalf("unexpected validation issue: %+v", issues[0])
	}
}

func TestCertificateMaterialRedactedFromPreviewReleaseAndAudit(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)
	certPEM, keyPEM := testHTTPServerCertificatePEM(t, "app.example.test")
	certPayload, _ := json.Marshal(map[string]string{
		"name":     "App TLS",
		"cert_pem": certPEM,
		"key_pem":  keyPEM,
	})
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/certificates", bytes.NewReader(certPayload)), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create certificate status = %d body=%s", rec.Code, rec.Body.String())
	}
	var certResponse struct {
		Item model.Certificate `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&certResponse); err != nil {
		t.Fatalf("decode certificate: %v", err)
	}

	appPayload, _ := json.Marshal(map[string]any{
		"name":    "TLS app",
		"mode":    "protect",
		"enabled": true,
		"hosts":   []map[string]any{{"host": "app.example.test", "is_primary": true}},
		"listeners": []map[string]any{
			{"port": 443, "protocol": "https", "certificate_id": certResponse.Item.ID, "enabled": true},
		},
		"upstreams": []map[string]any{{"name": "primary", "url": "http://upstream:8080", "weight": 1, "enabled": true}},
	})
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/applications", bytes.NewReader(appPayload)), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create tls app status = %d body=%s", rec.Code, rec.Body.String())
	}

	for _, path := range []string{"/api/v1/releases/preview", "/api/v1/audit-logs"} {
		req = withToken(httptest.NewRequest(http.MethodGet, path, nil), token)
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d body=%s", path, rec.Code, rec.Body.String())
		}
		assertNoCertificateMaterial(t, rec.Body.String(), certPEM, keyPEM)
	}

	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/releases", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("publish tls app status = %d body=%s", rec.Code, rec.Body.String())
	}
	assertNoCertificateMaterial(t, rec.Body.String(), certPEM, keyPEM)

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("post-publish audit status = %d body=%s", rec.Code, rec.Body.String())
	}
	assertNoCertificateMaterial(t, rec.Body.String(), certPEM, keyPEM)
}

func TestPublishPreviewReportsBridgeListenerDeploymentMode(t *testing.T) {
	handler := testServerWithConfig(t, func(cfg *config.Config) {
		cfg.GatewayListenerMode = "bridge-range"
		cfg.GatewayBridgePortRange = "80,443,9000-9002"
	})
	token := adminToken(t, handler)

	req := withToken(httptest.NewRequest(http.MethodGet, "/api/v1/releases/preview", nil), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Summary map[string]any `json:"summary"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	deployment, ok := response.Summary["listener_deployment_mode"].(map[string]any)
	if !ok {
		t.Fatalf("missing listener deployment mode: %+v", response.Summary)
	}
	if deployment["mode"] != "bridge-range" || deployment["bridge_range_config"] != true || deployment["raw_port_range"] != "80,443,9000-9002" {
		t.Fatalf("unexpected deployment summary: %+v", deployment)
	}
	ports, ok := deployment["port_range"].([]any)
	if !ok || len(ports) != 5 {
		t.Fatalf("unexpected deployment ports: %+v", deployment["port_range"])
	}
}

func TestCreateReleaseBlocksBridgeRangeListenerOutsideMappedPorts(t *testing.T) {
	handler := testServerWithConfig(t, func(cfg *config.Config) {
		cfg.GatewayListenerMode = "bridge-range"
		cfg.GatewayBridgePortRange = "80,443,9000-9002"
	})
	token := adminToken(t, handler)

	appPayload, _ := json.Marshal(map[string]any{
		"name":    "Bridge Range App",
		"mode":    "protect",
		"enabled": true,
		"hosts": []map[string]any{
			{"host": "bridge.example.test", "is_primary": true},
		},
		"listeners": []map[string]any{
			{"port": 9443, "protocol": "http", "enabled": true},
		},
		"upstreams": []map[string]any{
			{"name": "primary", "url": "http://upstream:8080", "weight": 1, "enabled": true},
		},
	})
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/applications", bytes.NewReader(appPayload)), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create app status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/releases", bytes.NewBufferString(`{"operator":"admin"}`)), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("release status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "outside configured bridge port range") {
		t.Fatalf("release error did not explain bridge range: %s", rec.Body.String())
	}
}

func TestReleaseRecordIncludesListenerActivationAndRollbackTarget(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	appPayload, _ := json.Marshal(map[string]any{
		"name":    "Example",
		"mode":    "protect",
		"enabled": true,
		"hosts": []map[string]any{
			{"host": "app.example.test", "is_primary": true},
		},
		"listeners": []map[string]any{
			{"port": 80, "protocol": "http", "enabled": true},
		},
		"upstreams": []map[string]any{
			{"name": "primary", "url": "http://upstream:8080", "weight": 1, "enabled": true},
		},
	})
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/applications", bytes.NewReader(appPayload)), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create app status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/releases", bytes.NewBufferString(`{"note":"manual publish"}`)), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("publish status = %d body=%s", rec.Code, rec.Body.String())
	}
	var publishResponse struct {
		Item model.PublishRecord `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&publishResponse); err != nil {
		t.Fatalf("decode publish record: %v", err)
	}
	if publishResponse.Item.Activation == nil {
		t.Fatalf("expected activation summary: %+v", publishResponse.Item)
	}
	activation := publishResponse.Item.Activation
	if activation.Applications != 1 || activation.ListenerCount != 1 || activation.HTTPSListenerCount != 0 || activation.ReloadStatus != "not-configured" || len(activation.ValidationErrors) != 0 {
		t.Fatalf("unexpected activation summary: %+v", activation)
	}
	if !strings.Contains(publishResponse.Item.Note, model.PublishActivationNotePrefix) {
		t.Fatalf("expected activation metadata in note: %s", publishResponse.Item.Note)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/releases", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list releases status = %d body=%s", rec.Code, rec.Body.String())
	}
	var listResponse struct {
		Items []model.PublishRecord `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&listResponse); err != nil {
		t.Fatalf("decode release list: %v", err)
	}
	if len(listResponse.Items) != 1 || listResponse.Items[0].Activation == nil || listResponse.Items[0].Activation.ListenerCount != 1 {
		t.Fatalf("release list missing activation summary: %+v", listResponse.Items)
	}

	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/releases/"+publishResponse.Item.Version+"/rollback", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("rollback status = %d body=%s", rec.Code, rec.Body.String())
	}
	var rollbackResponse struct {
		Item model.PublishRecord `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&rollbackResponse); err != nil {
		t.Fatalf("decode rollback record: %v", err)
	}
	if rollbackResponse.Item.Activation == nil || rollbackResponse.Item.Activation.RollbackTarget != publishResponse.Item.Version {
		t.Fatalf("rollback record missing target: %+v", rollbackResponse.Item)
	}
	listenerConf, err := os.ReadFile(filepath.Join(filepath.Dir(publishResponse.Item.ConfigPath), "listeners", "applications.conf"))
	if err != nil {
		t.Fatalf("read rolled back listener config: %v", err)
	}
	if !bytes.Contains(listenerConf, []byte("listen 80;")) {
		t.Fatalf("rollback did not restore listener artifact: %s", listenerConf)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs?resource_type=release", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("release audit status = %d body=%s", rec.Code, rec.Body.String())
	}
	var auditResponse struct {
		Items []model.AuditLog `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&auditResponse); err != nil {
		t.Fatalf("decode release audit: %v", err)
	}
	hasPublish := false
	hasRollback := false
	for _, item := range auditResponse.Items {
		if item.Action == "publish" && strings.Contains(item.Message, "reload_status=not-configured") {
			hasPublish = true
		}
		if item.Action == "rollback" && strings.Contains(item.Message, "rollback_target="+publishResponse.Item.Version) {
			hasRollback = true
		}
	}
	if !hasPublish || !hasRollback {
		t.Fatalf("expected publish and rollback audit summaries: %+v", auditResponse.Items)
	}
}

func TestReleaseRecordIncludesGatewayReloadResult(t *testing.T) {
	successScript := writeReloadScript(t, "reload-ok", "reload ok", 0)
	handler := testServerWithConfig(t, func(cfg *config.Config) {
		cfg.GatewayReloadCommand = successScript
	})
	token := adminToken(t, handler)
	createApplicationForRelease(t, handler, token)

	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/releases", nil), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("publish status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Item model.PublishRecord `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode publish: %v", err)
	}
	if response.Item.Activation == nil || response.Item.Activation.ReloadStatus != "reloaded" || response.Item.Activation.ReloadMessage != "reload ok" {
		t.Fatalf("unexpected reload activation: %+v", response.Item.Activation)
	}
}

func TestReleaseRecordBoundsGatewayReloadFailure(t *testing.T) {
	longMessage := strings.Repeat("reload failed ", 80)
	failureScript := writeReloadScript(t, "reload-fail", longMessage, 1)
	handler := testServerWithConfig(t, func(cfg *config.Config) {
		cfg.GatewayReloadCommand = failureScript
	})
	token := adminToken(t, handler)
	createApplicationForRelease(t, handler, token)

	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/releases", nil), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("publish status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Item model.PublishRecord `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode publish: %v", err)
	}
	if response.Item.Activation == nil || response.Item.Activation.ReloadStatus != "failed" {
		t.Fatalf("expected failed reload activation: %+v", response.Item.Activation)
	}
	if len(response.Item.Activation.ReloadMessage) > 480 {
		t.Fatalf("reload message was not bounded: %d", len(response.Item.Activation.ReloadMessage))
	}
}

func createApplicationForRelease(t *testing.T, handler http.Handler, token string) {
	t.Helper()
	appPayload, _ := json.Marshal(map[string]any{
		"name":    "Example",
		"mode":    "protect",
		"enabled": true,
		"hosts": []map[string]any{
			{"host": "app.example.test", "is_primary": true},
		},
		"listeners": []map[string]any{
			{"port": 80, "protocol": "http", "enabled": true},
		},
		"upstreams": []map[string]any{
			{"name": "primary", "url": "http://upstream:8080", "weight": 1, "enabled": true},
		},
	})
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/applications", bytes.NewReader(appPayload)), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create app status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func writeReloadScript(t *testing.T, name string, message string, exitCode int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		path := filepath.Join(t.TempDir(), name+".bat")
		body := "@echo off\necho " + message + "\nexit /b " + strconv.Itoa(exitCode) + "\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write reload script: %v", err)
		}
		return path
	}
	path := filepath.Join(t.TempDir(), name+".sh")
	body := "#!/bin/sh\necho " + strconv.Quote(message) + "\nexit " + strconv.Itoa(exitCode) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatalf("write reload script: %v", err)
	}
	return path
}

func TestVersionEndpointUsesBuildVersion(t *testing.T) {
	originalVersion := app.Version
	app.Version = "9.8.7-test"
	t.Cleanup(func() {
		app.Version = originalVersion
	})

	handler := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}

	var response struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Env     string `json:"env"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode version: %v", err)
	}
	if response.Name != "LiteWaf API" || response.Version != "9.8.7-test" || response.Env != "test" {
		t.Fatalf("unexpected version response: %+v", response)
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

func TestBlockedRejectedRecordsExplainDeniedTraffic(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	ingest := func(path string, body string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer gateway-secret")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("ingest %s status = %d body=%s", path, rec.Code, rec.Body.String())
		}
	}

	ingest("/api/v1/ingest/access-logs", `{"request_id":"denied-waf","application_id":2,"listener_port":443,"scheme":"https","host":"app.example.test","method":"GET","uri":"/login","status":403,"duration_ms":4,"client_ip":"192.0.2.20","user_agent":"curl","disposition":"blocked"}`)
	ingest("/api/v1/ingest/waf-events", `{"request_id":"denied-waf","application_id":2,"listener_port":443,"scheme":"https","host":"app.example.test","event_type":"rule","rule_id":17,"rule_type":"sqli","target":"args","module":"attack-protection","category":"managed","rule_name":"SQLi block","attack_type":"sqli","action":"block","disposition":"blocked","client_ip":"192.0.2.20","method":"GET","uri":"/login","summary":"union select"}`)

	ingest("/api/v1/ingest/waf-events", `{"request_id":"ban-source","application_id":3,"listener_port":80,"scheme":"http","event_type":"dynamic-ban","rule_id":3,"rule_type":"cc","target":"path","module":"cc-protection","category":"rate-limit","rule_name":"Login ban","action":"block","disposition":"blocked","client_ip":"192.0.2.30","method":"POST","uri":"/api/login","summary":"temporary ban created","ban_reason":"cc threshold","ban_duration_sec":600,"ban_remaining_sec":600}`)
	ingest("/api/v1/ingest/access-logs", `{"request_id":"denied-ban","application_id":3,"listener_port":80,"scheme":"http","host":"ban.example.test","method":"POST","uri":"/api/login","status":403,"duration_ms":3,"client_ip":"192.0.2.30","user_agent":"curl","disposition":"blocked"}`)

	ingest("/api/v1/ingest/access-logs", `{"request_id":"denied-access-reason","application_id":4,"host":"missing.example.test","method":"GET","uri":"/","status":404,"duration_ms":1,"client_ip":"192.0.2.40","user_agent":"curl","disposition":"rejected","reason_code":"unknown-host","reason":"site not configured"}`)
	ingest("/api/v1/ingest/access-logs", `{"request_id":"denied-unclassified","application_id":5,"host":"plain.example.test","method":"GET","uri":"/blocked","status":403,"duration_ms":2,"client_ip":"192.0.2.50","user_agent":"curl","disposition":"blocked"}`)

	req := withToken(httptest.NewRequest(http.MethodGet, "/api/v1/blocked-rejected-records", nil), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("denied records status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Items []model.DeniedRecord `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode denied records: %v", err)
	}
	byRequestID := map[string]model.DeniedRecord{}
	for _, item := range response.Items {
		byRequestID[item.RequestID] = item
	}
	if len(byRequestID) != 4 {
		t.Fatalf("expected four denied records, got %+v", response.Items)
	}
	if item := byRequestID["denied-waf"]; item.ExplanationSource != "waf-event" || item.CorrelationType != "request-id" || item.Module != "attack-protection" || item.RuleID != 17 || item.Reason != "union select" {
		t.Fatalf("unexpected WAF denied record: %+v", item)
	}
	if item := byRequestID["denied-ban"]; item.ExplanationSource != "dynamic-ban" || item.CorrelationType != "fallback" || item.DynamicBanReason != "cc threshold" {
		t.Fatalf("unexpected dynamic-ban denied record: %+v", item)
	}
	if item := byRequestID["denied-access-reason"]; item.ExplanationSource != "access-log" || item.ReasonCode != "unknown-host" || item.Reason != "site not configured" {
		t.Fatalf("unexpected access-log denied record: %+v", item)
	}
	if item := byRequestID["denied-unclassified"]; item.ExplanationSource != "unclassified" || item.Module != "" || item.RuleID != 0 {
		t.Fatalf("unexpected unclassified denied record: %+v", item)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/blocked-rejected-records?module=attack-protection&action=block&trigger_source=waf-event", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("filtered denied records status = %d body=%s", rec.Code, rec.Body.String())
	}
	response.Items = nil
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode filtered denied records: %v", err)
	}
	if len(response.Items) != 1 || response.Items[0].RequestID != "denied-waf" {
		t.Fatalf("unexpected filtered denied records: %+v", response.Items)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/blocked-rejected-records", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized denied records status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestApplicationScopedFieldsUseApplicationIDContract(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	appBody := bytes.NewBufferString(`{"name":"Scoped App","mode":"protect","hosts":[{"host":"scoped.example.test","is_primary":true}],"listeners":[{"port":8080,"protocol":"http","enabled":true}],"upstreams":[{"name":"primary","url":"http://upstream:8080","weight":1,"enabled":true}]}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/applications", appBody), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create application status = %d body=%s", rec.Code, rec.Body.String())
	}
	var appResponse struct {
		Item model.Application `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&appResponse); err != nil {
		t.Fatalf("decode application: %v", err)
	}

	ruleBody := bytes.NewBufferString(`{"name":"SQLi","type":"sqli","target":"args","action":"block","expression":"select","score":100}`)
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rules", ruleBody), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create rule status = %d body=%s", rec.Code, rec.Body.String())
	}
	var ruleResponse struct {
		Item model.Rule `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&ruleResponse); err != nil {
		t.Fatalf("decode rule: %v", err)
	}

	policyBody := bytes.NewBufferString(`{"name":"Default","application_ids":[` + strconv.FormatInt(appResponse.Item.ID, 10) + `],"rule_ids":[` + strconv.FormatInt(ruleResponse.Item.ID, 10) + `]}`)
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/policies", policyBody), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create policy status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, `"site_ids"`) {
		t.Fatalf("policy response leaked site_ids: %s", body)
	}
	var policyResponse struct {
		Item model.Policy `json:"item"`
	}
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&policyResponse); err != nil {
		t.Fatalf("decode policy: %v", err)
	}
	if len(policyResponse.Item.SiteIDs) != 1 || policyResponse.Item.SiteIDs[0] != appResponse.Item.ID {
		t.Fatalf("unexpected policy application_ids: %+v", policyResponse.Item)
	}

	ccBody := bytes.NewBufferString(`{"name":"API limit","application_id":` + strconv.FormatInt(appResponse.Item.ID, 10) + `,"match":{"path":"/api","path_match":"prefix","methods":["GET"]},"limit":{"counter":"client_ip","threshold":10,"window_sec":60},"action":{"type":"block"}}`)
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/cc-protection/rules", ccBody), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create cc with application_id status = %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"site_id"`) {
		t.Fatalf("cc response leaked site_id: %s", rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/cc-protection/rules?application_id="+strconv.FormatInt(appResponse.Item.ID, 10), nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list cc with application_id status = %d body=%s", rec.Code, rec.Body.String())
	}
	var ccList struct {
		Items []model.ProtectionRule `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&ccList); err != nil {
		t.Fatalf("decode cc list: %v", err)
	}
	if len(ccList.Items) != 1 || ccList.Items[0].SiteID != appResponse.Item.ID {
		t.Fatalf("unexpected cc list: %+v", ccList.Items)
	}

	ipBody := bytes.NewBufferString(`{"name":"Office","kind":"allow","target":"ip","value":"203.0.113.10","application_id":` + strconv.FormatInt(appResponse.Item.ID, 10) + `}`)
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/ip-access-lists", ipBody), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create ip access with application_id status = %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"site_id"`) {
		t.Fatalf("ip access response leaked site_id: %s", rec.Body.String())
	}
}

func TestObservabilityApplicationListenerFields(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/access-logs", bytes.NewBufferString(`{"request_id":"req-app-listener","application_id":5,"listener_port":8443,"scheme":"https","host":"App.EXAMPLE.test","method":"GET","uri":"/","status":200,"duration_ms":7,"client_ip":"192.0.2.70","user_agent":"curl","disposition":"proxied"}`))
	req.Header.Set("Authorization", "Bearer gateway-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("ingest access application fields status = %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"site_id"`) {
		t.Fatalf("access response leaked site_id: %s", rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/ingest/waf-events", bytes.NewBufferString(`{"request_id":"waf-app-listener","application_id":5,"listener_port":8443,"scheme":"https","host":"App.EXAMPLE.test","event_type":"rule","rule_id":17,"rule_type":"xss","target":"args","action":"block","disposition":"blocked","client_ip":"192.0.2.70","method":"GET","uri":"/search","summary":"matched"}`))
	req.Header.Set("Authorization", "Bearer gateway-secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("ingest waf application fields status = %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"site_id"`) {
		t.Fatalf("waf response leaked site_id: %s", rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/access-logs?application_id=5&listener_port=8443&scheme=https&host=app.example.test", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list access application fields status = %d body=%s", rec.Code, rec.Body.String())
	}
	var accessResponse struct {
		Items []model.AccessLog `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&accessResponse); err != nil {
		t.Fatalf("decode application access logs: %v", err)
	}
	if len(accessResponse.Items) != 1 || accessResponse.Items[0].SiteID != 5 || accessResponse.Items[0].ListenerPort != 8443 || accessResponse.Items[0].Scheme != "https" || accessResponse.Items[0].Host != "app.example.test" {
		t.Fatalf("unexpected application access logs: %+v", accessResponse.Items)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/attack-logs?application_id=5&listener_port=8443&scheme=https&host=app.example.test", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list waf application fields status = %d body=%s", rec.Code, rec.Body.String())
	}
	var wafResponse struct {
		Items []model.WAFEvent `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&wafResponse); err != nil {
		t.Fatalf("decode application waf logs: %v", err)
	}
	if len(wafResponse.Items) != 1 || wafResponse.Items[0].SiteID != 5 || wafResponse.Items[0].ListenerPort != 8443 || wafResponse.Items[0].Scheme != "https" || wafResponse.Items[0].Host != "app.example.test" {
		t.Fatalf("unexpected application waf logs: %+v", wafResponse.Items)
	}
}

func TestStatisticsReportAggregatesRealLogs(t *testing.T) {
	handler := testServerWithConfig(t, func(cfg *config.Config) {
		cfg.GeoIPDatabasePath = writeTestGeoIPDatabase(t)
	})
	token := adminToken(t, handler)
	now := time.Now().UTC().Format(time.RFC3339)

	accessPayloads := []string{
		`{"request_id":"report-1","application_id":5,"host":"app.example.test","method":"GET","uri":"/","status":200,"duration_ms":12,"client_ip":"8.8.8.8","user_agent":"Mozilla/5.0 (Windows NT 10.0) Chrome/120.0","referer":"https://search.example.com/result","geo_country":"伪造国家","geo_region":"伪造省","geo_city":"伪造市","geo_longitude":1,"geo_latitude":2,"disposition":"proxied","created_at":"` + now + `"}`,
		`{"request_id":"report-2","application_id":5,"host":"app.example.test","method":"GET","uri":"/static/app.js","status":404,"duration_ms":5,"client_ip":"1.1.1.1","user_agent":"curl/8.0","geo_country":"伪造国家","geo_longitude":1,"geo_latitude":2,"disposition":"blocked","created_at":"` + now + `"}`,
		`{"request_id":"report-other","application_id":6,"host":"other.example.test","method":"GET","uri":"/","status":200,"duration_ms":5,"client_ip":"9.9.9.9","user_agent":"curl/8.0","disposition":"proxied","created_at":"` + now + `"}`,
	}
	for _, payload := range accessPayloads {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/access-logs", bytes.NewBufferString(payload))
		req.Header.Set("Authorization", "Bearer gateway-secret")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("ingest report access status = %d body=%s", rec.Code, rec.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/waf-events", bytes.NewBufferString(`{"request_id":"report-waf","application_id":5,"event_type":"rule","rule_id":7,"rule_type":"xss","target":"args","action":"block","disposition":"blocked","client_ip":"198.51.100.11","method":"GET","uri":"/static/app.js","summary":"blocked","created_at":"`+now+`"}`))
	req.Header.Set("Authorization", "Bearer gateway-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("ingest report waf status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/reports/statistics?application_id=5&range=30d&scope=world&map_view=3d", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("statistics report status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Item model.StatisticsReport `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode statistics report: %v", err)
	}
	if response.Item.Cards.Requests != 2 || response.Item.Cards.PV != 1 || response.Item.Cards.UniqueIPs != 2 || response.Item.Cards.AttackIPs != 1 {
		t.Fatalf("unexpected report cards: %+v", response.Item.Cards)
	}
	if response.Item.Cards.Errors4xx != 1 || response.Item.Cards.Blocked4xx != 1 || response.Item.Cards.ErrorRate4xx != 50 {
		t.Fatalf("unexpected 4xx metrics: %+v", response.Item.Cards)
	}
	if response.Item.Geo.Scope != "world" || response.Item.Geo.MapView != "3d" || len(response.Item.Geo.Ranking) != 2 {
		t.Fatalf("unexpected world geo report: %+v", response.Item.Geo)
	}
	if response.Item.Geo.Ranking[0].Name == "伪造国家" || response.Item.Geo.Ranking[1].Name == "伪造国家" {
		t.Fatalf("statistics report used caller-supplied geo fields: %+v", response.Item.Geo.Ranking)
	}
	if len(response.Item.Referers.Domains) != 1 || response.Item.Referers.Domains[0].Key != "search.example.com" {
		t.Fatalf("unexpected referers: %+v", response.Item.Referers)
	}
	if len(response.Item.Clients.Browsers) == 0 || len(response.Item.Statuses) == 0 || len(response.Item.QPS) == 0 {
		t.Fatalf("expected report breakdowns: %+v", response.Item)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/reports/statistics?application_id=5&range=30d&scope=china&map_view=3d", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("statistics china report status = %d body=%s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode china statistics report: %v", err)
	}
	if response.Item.Geo.Scope != "china" || response.Item.Geo.MapView != "2d" || len(response.Item.Geo.Ranking) != 1 || response.Item.Geo.Ranking[0].Name != "北京" {
		t.Fatalf("unexpected china geo report: %+v", response.Item.Geo)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/reports/statistics?application_id=5&range=30d&scope=world&metric=blocked", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("statistics blocked geo report status = %d body=%s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode blocked statistics report: %v", err)
	}
	if len(response.Item.Geo.Ranking) != 1 || response.Item.Geo.Ranking[0].Name != "新加坡" {
		t.Fatalf("unexpected blocked geo report: %+v", response.Item.Geo)
	}
}

func TestStatisticsReportRealtimeQPSUsesFiveSecondBucketTotals(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)
	until := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	since := until.Add(-time.Hour)
	qpsStart := until.Add(-3 * time.Minute)
	accessTimes := []time.Time{
		qpsStart.Add(5 * time.Second),
		until.Add(-10 * time.Second),
		until.Add(-9 * time.Second),
		until.Add(-181 * time.Second),
	}

	for index, createdAt := range accessTimes {
		payload := `{"request_id":"qps-` + strconv.Itoa(index) + `","application_id":5,"host":"app.example.test","method":"GET","uri":"/","status":200,"duration_ms":12,"client_ip":"8.8.8.8","user_agent":"curl","disposition":"proxied","created_at":"` + createdAt.Format(time.RFC3339) + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/access-logs", bytes.NewBufferString(payload))
		req.Header.Set("Authorization", "Bearer gateway-secret")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("ingest qps access status = %d body=%s", rec.Code, rec.Body.String())
		}
	}

	req := withToken(httptest.NewRequest(http.MethodGet, "/api/v1/reports/statistics?application_id=5&since="+since.Format(time.RFC3339)+"&until="+until.Format(time.RFC3339), nil), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("statistics qps report status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Item model.StatisticsReport `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode qps statistics report: %v", err)
	}
	qps := response.Item.QPS
	if len(qps) != 37 {
		t.Fatalf("expected 37 qps buckets for 3 minute window, got %d", len(qps))
	}
	if qps[0].Time != qpsStart.Format(time.RFC3339) || qps[len(qps)-1].Time != until.Format(time.RFC3339) {
		t.Fatalf("unexpected qps range: first=%s last=%s", qps[0].Time, qps[len(qps)-1].Time)
	}
	for index := 1; index < len(qps); index++ {
		previous, err := time.Parse(time.RFC3339, qps[index-1].Time)
		if err != nil {
			t.Fatalf("parse previous qps time: %v", err)
		}
		current, err := time.Parse(time.RFC3339, qps[index].Time)
		if err != nil {
			t.Fatalf("parse current qps time: %v", err)
		}
		if current.Sub(previous) != 5*time.Second {
			t.Fatalf("expected qps bucket interval 5s at index %d, got %s", index, current.Sub(previous))
		}
	}
	if qps[1].Value != 1 {
		t.Fatalf("expected one request in five seconds to be counted as 1, got %+v", qps[1])
	}
	if qps[34].Value != 2 {
		t.Fatalf("expected two requests in five seconds to be counted as 2, got %+v", qps[34])
	}
	if qps[2].Value != 0 || qps[0].Value != 0 {
		t.Fatalf("expected empty qps buckets to be zero-filled: first=%+v third=%+v", qps[0], qps[2])
	}
}

func TestAccessLogGeoIPIgnoresPayloadGeoAndReportsMissingDatabase(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)
	now := time.Now().UTC().Format(time.RFC3339)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/access-logs", bytes.NewBufferString(`{"request_id":"geo-spoof","application_id":5,"host":"app.example.test","method":"GET","uri":"/","status":200,"duration_ms":12,"client_ip":"8.8.8.8","user_agent":"curl","geo_country":"伪造国家","geo_region":"伪造省","geo_city":"伪造市","geo_longitude":1,"geo_latitude":2,"disposition":"proxied","created_at":"`+now+`"}`))
	req.Header.Set("Authorization", "Bearer gateway-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("ingest spoofed geo status = %d body=%s", rec.Code, rec.Body.String())
	}
	var createResponse struct {
		Item model.AccessLog `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&createResponse); err != nil {
		t.Fatalf("decode spoofed geo ingest: %v", err)
	}
	if createResponse.Item.GeoCountry != "" || createResponse.Item.GeoRegion != "" || createResponse.Item.GeoResolved || createResponse.Item.GeoUnresolvedReason != "geoip-database-not-configured" {
		t.Fatalf("expected spoofed geo to be ignored with missing database diagnostic, got %+v", createResponse.Item)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/reports/statistics?application_id=5&range=30d&scope=world", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("statistics report status = %d body=%s", rec.Code, rec.Body.String())
	}
	var reportResponse struct {
		Item model.StatisticsReport `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&reportResponse); err != nil {
		t.Fatalf("decode missing geoip report: %v", err)
	}
	if len(reportResponse.Item.Geo.Ranking) != 0 || len(reportResponse.Item.Geo.Diagnostics) == 0 {
		t.Fatalf("expected empty geo ranking with diagnostics, got %+v", reportResponse.Item.Geo)
	}
}

func TestStatisticsReportChinaScopeForces2D(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	req := withToken(httptest.NewRequest(http.MethodGet, "/api/v1/reports/statistics?scope=china&map_view=3d", nil), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("statistics china report status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Item model.StatisticsReport `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode statistics china report: %v", err)
	}
	if response.Item.Geo.Scope != "china" || response.Item.Geo.MapView != "2d" {
		t.Fatalf("expected china scope to force 2d: %+v", response.Item.Geo)
	}
	if response.Item.Cards.Requests != 0 || len(response.Item.Geo.Ranking) != 0 {
		t.Fatalf("expected empty real report state: %+v", response.Item)
	}
}

func TestDynamicBanApplicationIDContract(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/waf-events", bytes.NewBufferString(`{"request_id":"ban-app","application_id":9,"listener_port":443,"scheme":"https","event_type":"dynamic-ban","rule_id":3,"rule_type":"cc","target":"path","module":"cc-protection","category":"rate-limit","rule_name":"Login ban","action":"block","disposition":"blocked","client_ip":"198.51.100.90","method":"POST","uri":"/api/login","summary":"temporary ban created","ban_reason":"cc-protection:3","ban_duration_sec":600,"ban_remaining_sec":600}`))
	req.Header.Set("Authorization", "Bearer gateway-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("ingest dynamic ban application_id status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-bans?application_id=9&status=active", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list dynamic bans application_id status = %d body=%s", rec.Code, rec.Body.String())
	}
	var listResponse struct {
		Items []model.DynamicBan `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&listResponse); err != nil {
		t.Fatalf("decode application dynamic bans: %v", err)
	}
	if len(listResponse.Items) != 1 || listResponse.Items[0].SiteID != 9 || listResponse.Items[0].ListenerPort != 443 || listResponse.Items[0].Scheme != "https" {
		t.Fatalf("unexpected application dynamic bans: %+v", listResponse.Items)
	}
	if strings.Contains(rec.Body.String(), `"site_id"`) {
		t.Fatalf("dynamic ban list leaked site_id: %s", rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-bans/unban", bytes.NewBufferString(`{"application_id":9,"client_ip":"198.51.100.90"}`)), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unban dynamic ban application_id status = %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"site_id"`) {
		t.Fatalf("dynamic ban clear leaked site_id: %s", rec.Body.String())
	}
	var clearResponse struct {
		Item model.DynamicBanClearResult `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&clearResponse); err != nil {
		t.Fatalf("decode application clear result: %v", err)
	}
	if clearResponse.Item.SiteID != 9 || clearResponse.Item.Status != "cleared" {
		t.Fatalf("unexpected application clear result: %+v", clearResponse.Item)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-bans/clears?application_id=9&listener_port=443&scheme=https&since_revision=0", nil)
	req.Header.Set("Authorization", "Bearer gateway-secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear feed application listener status = %d body=%s", rec.Code, rec.Body.String())
	}
	var feedResponse struct {
		Items []model.DynamicBanClearResult `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&feedResponse); err != nil {
		t.Fatalf("decode application clear feed: %v", err)
	}
	if len(feedResponse.Items) != 1 || feedResponse.Items[0].SiteID != 9 || feedResponse.Items[0].ListenerPort != 443 || feedResponse.Items[0].Scheme != "https" {
		t.Fatalf("unexpected application listener clear feed: %+v", feedResponse.Items)
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

func TestObservabilitySummaryIncludesHourlyTrends(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)
	until := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	accessTime := until.Add(-2 * time.Hour).Format(time.RFC3339)
	wafTime := until.Add(-1 * time.Hour).Format(time.RFC3339)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/access-logs", bytes.NewBufferString(`{"request_id":"trend-access","application_id":2,"host":"app.example.test","method":"GET","uri":"/login","status":403,"duration_ms":4,"client_ip":"192.0.2.20","user_agent":"curl","disposition":"blocked","created_at":"`+accessTime+`"}`))
	req.Header.Set("Authorization", "Bearer gateway-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("ingest trend access status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/ingest/waf-events", bytes.NewBufferString(`{"request_id":"trend-waf","application_id":2,"event_type":"rule","rule_id":17,"rule_type":"sqli","target":"args","module":"attack-protection","category":"managed","rule_name":"SQLi block","attack_type":"sqli","action":"block","disposition":"blocked","client_ip":"192.0.2.20","method":"GET","uri":"/login","summary":"blocked","created_at":"`+wafTime+`"}`))
	req.Header.Set("Authorization", "Bearer gateway-secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("ingest trend waf status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/observability/summary?until="+until.Format(time.RFC3339), nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("summary trend status = %d body=%s", rec.Code, rec.Body.String())
	}
	var summaryResponse struct {
		Item model.ObservabilitySummary `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&summaryResponse); err != nil {
		t.Fatalf("decode summary trend: %v", err)
	}
	item := summaryResponse.Item
	if len(item.RequestTrend) != 24 || len(item.BlockedTrend) != 24 || len(item.WAFMatchTrend) != 24 {
		t.Fatalf("unexpected trend lengths: request=%d blocked=%d waf=%d", len(item.RequestTrend), len(item.BlockedTrend), len(item.WAFMatchTrend))
	}
	if item.RequestTrend[0].Time != until.Add(-23*time.Hour).Format(time.RFC3339) || item.RequestTrend[23].Time != until.Format(time.RFC3339) {
		t.Fatalf("unexpected trend range: first=%s last=%s", item.RequestTrend[0].Time, item.RequestTrend[23].Time)
	}
	if item.RequestTrend[21].Value != 1 || item.BlockedTrend[21].Value != 1 {
		t.Fatalf("unexpected access trend buckets: request=%+v blocked=%+v", item.RequestTrend[21], item.BlockedTrend[21])
	}
	if item.WAFMatchTrend[22].Value != 1 || item.BlockedTrend[22].Value != 1 {
		t.Fatalf("unexpected waf trend buckets: waf=%+v blocked=%+v", item.WAFMatchTrend[22], item.BlockedTrend[22])
	}
	if item.RequestTrend[20].Value != 0 || item.WAFMatchTrend[23].Value != 0 {
		t.Fatalf("expected zero-count buckets around populated values: request20=%v waf23=%v", item.RequestTrend[20].Value, item.WAFMatchTrend[23].Value)
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

func TestAccessLogsPaginationMetadata(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	for i := 1; i <= 3; i++ {
		body := bytes.NewBufferString(`{"request_id":"page-` + strconv.Itoa(i) + `","application_id":1,"host":"app.example.test","method":"GET","uri":"/page/` + strconv.Itoa(i) + `","status":200,"duration_ms":4,"client_ip":"198.51.100.` + strconv.Itoa(i) + `","user_agent":"curl","disposition":"proxied"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/access-logs", body)
		req.Header.Set("Authorization", "Bearer gateway-secret")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("ingest access log %d status = %d body=%s", i, rec.Code, rec.Body.String())
		}
	}

	req := withToken(httptest.NewRequest(http.MethodGet, "/api/v1/access-logs?limit=2&offset=1", nil), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list access logs status = %d body=%s", rec.Code, rec.Body.String())
	}
	var page struct {
		Items  []model.AccessLog `json:"items"`
		Total  int               `json:"total"`
		Limit  int               `json:"limit"`
		Offset int               `json:"offset"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&page); err != nil {
		t.Fatalf("decode page: %v", err)
	}
	if page.Total != 3 || page.Limit != 2 || page.Offset != 1 || len(page.Items) != 2 {
		t.Fatalf("unexpected pagination metadata: %+v", page)
	}
	if page.Items[0].RequestID != "page-2" || page.Items[1].RequestID != "page-1" {
		t.Fatalf("unexpected paged order: %+v", page.Items)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/access-logs?client_ip=198.51.100.2&limit=20", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("filtered list status = %d body=%s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&page); err != nil {
		t.Fatalf("decode filtered page: %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].ClientIP != "198.51.100.2" {
		t.Fatalf("unexpected filtered page: %+v", page)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/access-logs?client_ip=203.0.113.200&limit=20", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("empty filtered list status = %d body=%s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&page); err != nil {
		t.Fatalf("decode empty page: %v", err)
	}
	if page.Total != 0 || len(page.Items) != 0 {
		t.Fatalf("unexpected empty page: %+v", page)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/access-logs?limit=-1", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("negative pagination status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDynamicBanListUnbanClearFeedAndAudit(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/waf-events", bytes.NewBufferString(`{"request_id":"ban-1","site_id":7,"event_type":"dynamic-ban","rule_id":3,"rule_type":"cc","target":"path","module":"cc-protection","category":"rate-limit","rule_name":"Login ban","action":"block","disposition":"blocked","client_ip":"198.51.100.10","method":"POST","uri":"/api/login","summary":"cc protection temporary ban created","ban_reason":"cc-protection:3","ban_duration_sec":600,"ban_remaining_sec":600}`))
	req.Header.Set("Authorization", "Bearer gateway-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("ingest dynamic ban status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-bans?site_id=7&status=active", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list dynamic bans status = %d body=%s", rec.Code, rec.Body.String())
	}
	var listResponse struct {
		Items []model.DynamicBan `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&listResponse); err != nil {
		t.Fatalf("decode active bans: %v", err)
	}
	if len(listResponse.Items) != 1 || listResponse.Items[0].ClientIP != "198.51.100.10" || listResponse.Items[0].Status != "active" {
		t.Fatalf("unexpected active ban list: %+v", listResponse.Items)
	}

	readonlyToken, _, err := auth.IssueToken("test-secret", "readonly", 99, "readonly", 3600000000000)
	if err != nil {
		t.Fatalf("issue readonly token: %v", err)
	}
	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-bans?site_id=7", nil), readonlyToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("readonly list status = %d body=%s", rec.Code, rec.Body.String())
	}
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-bans/unban", bytes.NewBufferString(`{"site_id":7,"client_ip":"198.51.100.10"}`)), readonlyToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly unban status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-bans/unban", bytes.NewBufferString(`{"site_id":7,"client_ip":"198.51.100.10"}`)), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unban status = %d body=%s", rec.Code, rec.Body.String())
	}
	var clearResponse struct {
		Item model.DynamicBanClearResult `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&clearResponse); err != nil {
		t.Fatalf("decode clear result: %v", err)
	}
	if clearResponse.Item.Status != "cleared" || clearResponse.Item.Revision == 0 {
		t.Fatalf("unexpected clear response: %+v", clearResponse.Item)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-bans/clears?since_revision=0", nil)
	req.Header.Set("Authorization", "Bearer gateway-secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear feed status = %d body=%s", rec.Code, rec.Body.String())
	}
	var feedResponse struct {
		Items []model.DynamicBanClearResult `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&feedResponse); err != nil {
		t.Fatalf("decode clear feed: %v", err)
	}
	if len(feedResponse.Items) != 1 || feedResponse.Items[0].ClientIP != "198.51.100.10" {
		t.Fatalf("unexpected clear feed: %+v", feedResponse.Items)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs?resource_type=dynamic_ban&action=unban", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit query status = %d body=%s", rec.Code, rec.Body.String())
	}
	var auditResponse struct {
		Items []model.AuditLog `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&auditResponse); err != nil {
		t.Fatalf("decode audit logs: %v", err)
	}
	if len(auditResponse.Items) != 1 || auditResponse.Items[0].ResourceID != "7:198.51.100.10" || auditResponse.Items[0].Result != "cleared" {
		t.Fatalf("unexpected audit logs: %+v", auditResponse.Items)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-bans?site_id=7&status=active", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list active after unban status = %d body=%s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&listResponse); err != nil {
		t.Fatalf("decode active bans after unban: %v", err)
	}
	if len(listResponse.Items) != 0 {
		t.Fatalf("expected no active bans after unban, got %+v", listResponse.Items)
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
	if len(overviewResponse.Item.Modules) != 8 {
		t.Fatalf("expected implemented module rows, got %+v", overviewResponse.Item.Modules)
	}
	if !moduleExists(overviewResponse.Item.Modules, "ip-access-list") {
		t.Fatalf("overview missing ip access-list module: %+v", overviewResponse.Item.Modules)
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

	body := bytes.NewBufferString(`{"name":"Admin challenge","site_id":3,"priority":70,"match":{"path":"/admin","path_match":"prefix","methods":["get","POST"]},"challenge":{"mode":"captcha","verify_ttl_sec":600,"failure_action":"block","behavior_enabled":true,"behavior_threshold":60,"device_binding":true,"search_engine_bypass":true,"failure_message":"验证失败，请稍后重试","privacy_notice":"仅使用浏览器信号完成本地验证"}}`)
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
	if createResponse.Item.Challenge == nil || createResponse.Item.Challenge.Mode != "captcha" || createResponse.Item.Challenge.VerifyTTL != 600 || createResponse.Item.Challenge.FailureAction != "block" {
		t.Fatalf("unexpected bot protection challenge: %+v", createResponse.Item.Challenge)
	}
	if !createResponse.Item.Challenge.BehaviorEnabled || createResponse.Item.Challenge.BehaviorThreshold != 60 || !createResponse.Item.Challenge.DeviceBinding || !createResponse.Item.Challenge.SearchEngineBypass {
		t.Fatalf("unexpected bot protection enhancement config: %+v", createResponse.Item.Challenge)
	}
	if createResponse.Item.Challenge.FailureMessage == "" || createResponse.Item.Challenge.PrivacyNotice == "" {
		t.Fatalf("expected bot protection message fields: %+v", createResponse.Item.Challenge)
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
		`{"name":"bad","match":{"path":"/admin","path_match":"prefix"},"challenge":{"mode":"turnstile","verify_ttl_sec":300,"failure_action":"block"}}`,
		`{"name":"bad","match":{"path":"/admin","path_match":"prefix"},"challenge":{"mode":"js-challenge","verify_ttl_sec":0,"failure_action":"block"}}`,
		`{"name":"bad","match":{"path":"/admin","path_match":"prefix"},"challenge":{"mode":"js-challenge","verify_ttl_sec":300,"failure_action":"captcha"}}`,
		`{"name":"bad","priority":-1,"match":{"path":"/admin","path_match":"prefix"},"challenge":{"mode":"js-challenge","verify_ttl_sec":300,"failure_action":"block"}}`,
		`{"name":"bad","match":{"path":"/admin","path_match":"prefix"},"challenge":{"mode":"js-challenge","verify_ttl_sec":300,"failure_action":"block","behavior_enabled":true,"behavior_threshold":101}}`,
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

func TestIPAccessListCRUDAndAccessControlDecoupling(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	body := bytes.NewBufferString(`{"name":"Office allow","kind":"allow","target":"ip","value":"203.0.113.10","site_id":7,"priority":80}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/ip-access-lists", body), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create ip access list status = %d body=%s", rec.Code, rec.Body.String())
	}
	var createResponse struct {
		Item model.IPAccessListEntry `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&createResponse); err != nil {
		t.Fatalf("decode ip access list create: %v", err)
	}
	if createResponse.Item.NormalizedValue != "203.0.113.10" || createResponse.Item.IPFamily != "ipv4" || createResponse.Item.PrefixLength != 32 {
		t.Fatalf("unexpected normalized ip entry: %+v", createResponse.Item)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/ip-access-lists", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list ip access list status = %d body=%s", rec.Code, rec.Body.String())
	}
	var ipListResponse struct {
		Items []model.IPAccessListEntry `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&ipListResponse); err != nil {
		t.Fatalf("decode ip access list: %v", err)
	}
	if len(ipListResponse.Items) != 1 {
		t.Fatalf("expected 1 ip access-list entry, got %+v", ipListResponse.Items)
	}

	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/access-lists", bytes.NewBufferString(`{"name":"old"}`)), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("legacy access-lists route status = %d body=%s", rec.Code, rec.Body.String())
	}

	accessBody := bytes.NewBufferString(`{"name":"Source block","match":{"target":"ip","value":"203.0.113.10"},"action":{"type":"block"}}`)
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/access-control/rules", accessBody), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("access control source ip status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/access-control/rules?site_id=7&enabled=true", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list access control status = %d body=%s", rec.Code, rec.Body.String())
	}
	var accessControlResponse struct {
		Items []model.ProtectionRule `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&accessControlResponse); err != nil {
		t.Fatalf("decode access control list: %v", err)
	}
	if len(accessControlResponse.Items) != 0 {
		t.Fatalf("ip access-list entries must not be returned by access control, got %+v", accessControlResponse.Items)
	}
}

func TestAccessControlRuleWriteLifecycleAndAudit(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	body := bytes.NewBufferString(`{"name":"Admin path","site_id":3,"priority":50,"match":{"target":"path","path":"/admin","path_match":"prefix"},"action":{"type":"block"}}`)
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
	if createResponse.Item.Match.Target != "path" || createResponse.Item.Match.Path != "/admin" || createResponse.Item.Action.Type != "block" || createResponse.Item.Priority != 50 {
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

func TestCCProtectionAdvancedCountersAndPreview(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	body := bytes.NewBufferString(`{"name":"Session API glob","site_id":3,"match":{"path":"/api/*/login","path_match":"glob","methods":["POST"]},"limit":{"counter":"session","session_source":"cookie","session_name":"sid","threshold":5,"window_sec":60,"ban_duration_sec":120},"action":{"type":"block"}}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/cc-protection/rules", body), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create advanced cc status = %d body=%s", rec.Code, rec.Body.String())
	}
	var createResponse struct {
		Item model.ProtectionRule `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&createResponse); err != nil {
		t.Fatalf("decode advanced cc: %v", err)
	}
	if createResponse.Item.Match.PathMatch != "glob" || createResponse.Item.Limit.Counter != "session" || createResponse.Item.Limit.SessionName != "sid" {
		t.Fatalf("advanced cc fields not preserved: %+v", createResponse.Item)
	}

	previewBody := bytes.NewBufferString(`{"site_id":3,"path":"/api/v1/login","method":"POST","client_ip":"198.51.100.8"}`)
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/cc-protection/preview", previewBody), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview status = %d body=%s", rec.Code, rec.Body.String())
	}
	var previewResponse struct {
		Item ccProtectionPreviewResponse `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&previewResponse); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if len(previewResponse.Item.Matches) != 1 || !previewResponse.Item.Matches[0].Partial {
		t.Fatalf("expected one partial session match, got %+v", previewResponse.Item.Matches)
	}
	if !strings.Contains(previewResponse.Item.Matches[0].CounterKey, "missing-session") {
		t.Fatalf("expected missing session explanation in counter key, got %+v", previewResponse.Item.Matches[0])
	}

	previewBody = bytes.NewBufferString(`{"site_id":3,"path":"/static/app.js","method":"GET"}`)
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/cc-protection/preview", previewBody), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("no-match preview status = %d body=%s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&previewResponse); err != nil {
		t.Fatalf("decode no-match preview: %v", err)
	}
	if len(previewResponse.Item.Matches) != 0 {
		t.Fatalf("expected no fabricated preview matches, got %+v", previewResponse.Item.Matches)
	}

	readonlyToken, _, err := auth.IssueToken("test-secret", "readonly", 99, "readonly", 3600000000000)
	if err != nil {
		t.Fatalf("issue readonly token: %v", err)
	}
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/cc-protection/preview", bytes.NewBufferString(`{"site_id":3,"path":"/api/v1/login","method":"POST","session_id":"abc"}`)), readonlyToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("readonly preview status = %d body=%s", rec.Code, rec.Body.String())
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

	ipBody := bytes.NewBufferString(`{"name":"办公出口放行","kind":"allow","target":"ip","value":"203.0.113.10","site_id":1,"enabled":true,"priority":10}`)
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/ip-access-lists", ipBody), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create ip access list status = %d body=%s", rec.Code, rec.Body.String())
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
	var ccModule, ipModule, accessModule model.ProtectionModuleOverview
	for _, module := range overviewResponse.Item.Modules {
		switch module.Key {
		case "cc-protection":
			ccModule = module
		case "ip-access-list":
			ipModule = module
		case "access-control":
			accessModule = module
		}
	}
	if ccModule.CompatibilitySource != "rate_limits" || ccModule.Enabled != 1 || len(ccModule.Warnings) == 0 {
		t.Fatalf("unexpected cc overview: %+v", ccModule)
	}
	if len(ccModule.RiskDetails) == 0 || ccModule.RiskDetails[0].Scope == "" || ccModule.RiskDetails[0].Impact == "" || ccModule.RiskDetails[0].Recommendation == "" {
		t.Fatalf("cc overview missing structured risk details: %+v", ccModule)
	}
	if ipModule.Route != "/ip-access-lists" || ipModule.Allow != 1 || ipModule.Enabled != 1 || ipModule.CompatibilitySource != "" {
		t.Fatalf("unexpected ip access-list overview: %+v", ipModule)
	}
	if accessModule.CompatibilitySource != "" || accessModule.Allow != 0 || accessModule.Rules != 0 {
		t.Fatalf("unexpected access overview: %+v", accessModule)
	}
	if len(overviewResponse.Item.Risks) < 1 {
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
	risks, ok := summary["risk_warnings"].([]any)
	if !ok || len(risks) == 0 {
		t.Fatalf("preview missing structured risks: %+v", summary)
	}
	firstRisk, ok := risks[0].(map[string]any)
	if !ok || firstRisk["scope"] == "" || firstRisk["impact"] == "" || firstRisk["recommendation"] == "" {
		t.Fatalf("preview risk missing actionable context: %+v", risks[0])
	}
	ipSummary, ok := summary["ip_access_list"].(map[string]any)
	if !ok || int(ipSummary["enabled"].(float64)) != 1 || int(ipSummary["allow"].(float64)) != 1 {
		t.Fatalf("preview lost ip access-list counts: %+v", summary)
	}
	if int(summary["rate_limits"].(float64)) != 1 {
		t.Fatalf("preview lost rate limit count: %+v", summary)
	}
	if _, ok := summary["access_lists"]; ok {
		t.Fatalf("preview must not expose legacy access_lists count: %+v", summary)
	}
	if summary["compatibility_diagnostics"] == nil {
		t.Fatalf("preview missing compatibility diagnostics: %+v", summary)
	}
}

func TestPublishPreviewSummarizesAdvancedCCRisk(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)

	body := bytes.NewBufferString(`{"name":"Broad glob low threshold","site_id":1,"match":{"path":"/*","path_match":"glob","methods":[]},"limit":{"counter":"device","device_strategy":"coarse","threshold":10,"window_sec":60,"ban_duration_sec":300},"action":{"type":"rate-limit"}}`)
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/cc-protection/rules", body), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create advanced risk rule status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/releases/preview", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Summary map[string]any `json:"summary"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode publish preview: %v", err)
	}
	cc, ok := response.Summary["cc_protection"].(map[string]any)
	if !ok {
		t.Fatalf("missing cc protection summary: %+v", response.Summary)
	}
	if int(cc["advanced_counters"].(float64)) != 1 || int(cc["glob_rules"].(float64)) != 1 || int(cc["block"].(float64)) != 1 {
		t.Fatalf("advanced cc counts missing: %+v", cc)
	}
	warnings, ok := cc["warnings"].([]any)
	if !ok || len(warnings) == 0 {
		t.Fatalf("expected advanced cc warning: %+v", cc)
	}
	details, ok := cc["risk_details"].([]any)
	if !ok || len(details) == 0 {
		t.Fatalf("expected advanced cc risk details: %+v", cc)
	}
	firstDetail, ok := details[0].(map[string]any)
	if !ok || firstDetail["rule_name"] == "" || firstDetail["scope"] == "" || firstDetail["action"] == "" {
		t.Fatalf("advanced cc risk details missing context: %+v", details[0])
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
		`{"name":"bad","match":{"path":"/api/**","path_match":"glob"},"limit":{"counter":"client_ip","threshold":1,"window_sec":1},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"path":"/api","path_match":"exact","methods":["TRACE"]},"limit":{"counter":"client_ip","threshold":1,"window_sec":1},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"path":"/api","path_match":"exact"},"limit":{"counter":"cookie","threshold":1,"window_sec":1},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"path":"/api","path_match":"exact"},"limit":{"counter":"session","threshold":1,"window_sec":1},"action":{"type":"block"}}`,
		`{"name":"bad","match":{"path":"/api","path_match":"exact"},"limit":{"counter":"device","device_strategy":"raw","threshold":1,"window_sec":1},"action":{"type":"block"}}`,
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

func TestRuleCommunityProviderAdaptersSyncPreviewImportAndSafety(t *testing.T) {
	handler := testServer(t)
	token := adminToken(t, handler)
	packageBody := `{"id":"provider-pack","name":"provider-pack","version":"v1","author":"LiteWaf","license":"MIT","compatibility":"litewaf-rule-package-v1","defaults":{"enabled":false,"review_status":"pending-review"},"rules":[{"id":"provider-xss","name":"Provider XSS","type":"xss","target":"args","action":"block","expression":"(?i)<svg","score":70}]}`
	catalog := map[string]any{
		"schema_version": "litewaf-rule-catalog-v1",
		"packages": []map[string]any{
			{"id": "provider-pack", "name": "Provider Pack", "version": "v1", "compatibility": "litewaf-rule-package-v1", "package": json.RawMessage(packageBody)},
		},
	}
	data, err := json.Marshal(catalog)
	if err != nil {
		t.Fatalf("marshal provider catalog: %v", err)
	}
	catalogPath := t.TempDir() + "/provider-catalog.json"
	if err := os.WriteFile(catalogPath, data, 0o644); err != nil {
		t.Fatalf("write provider catalog: %v", err)
	}

	providerBody := `{"name":"Provider feed","provider_type":"https-catalog","endpoint":` + strconv.Quote(catalogPath) + `,"auth_mode":"bearer-token","enabled":true,"timeout_sec":5,"retry_policy":{"max_attempts":2,"backoff_sec":1},"credential":{"alias":"prod"},"credential_secret":"provider-secret-token"}`
	req := withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/providers", bytes.NewBufferString(providerBody)), token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create provider status = %d body=%s", rec.Code, rec.Body.String())
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("provider-secret-token")) || bytes.Contains(rec.Body.Bytes(), []byte("credential_secret")) {
		t.Fatalf("provider response leaked secret: %s", rec.Body.String())
	}
	var providerResponse struct {
		Item model.RuleProviderAdapter `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&providerResponse); err != nil {
		t.Fatalf("decode provider: %v", err)
	}
	provider := providerResponse.Item
	if provider.Credential.LastFour != "oken" || provider.Credential.Status != "configured" || provider.HealthStatus != "never-synced" {
		t.Fatalf("unexpected redacted provider metadata: %+v", provider)
	}

	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/providers/"+strconv.FormatInt(provider.ID, 10)+"/validate", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("validate provider status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/providers/"+strconv.FormatInt(provider.ID, 10)+"/sync", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sync provider status = %d body=%s", rec.Code, rec.Body.String())
	}
	var syncResponse struct {
		Item  model.RuleProviderAdapter   `json:"item"`
		Items []model.RuleProviderPackage `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&syncResponse); err != nil {
		t.Fatalf("decode sync: %v", err)
	}
	if syncResponse.Item.HealthStatus != "healthy" || syncResponse.Item.PackageCount != 1 || len(syncResponse.Items) != 1 {
		t.Fatalf("unexpected sync response: %+v", syncResponse)
	}
	if syncResponse.Items[0].ProviderPackageRef != "provider-pack@v1" || syncResponse.Items[0].EntitlementState != "allowed" {
		t.Fatalf("unexpected provider package: %+v", syncResponse.Items[0])
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list rules before import status = %d body=%s", rec.Code, rec.Body.String())
	}
	var beforeRules struct {
		Items []model.Rule `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&beforeRules); err != nil {
		t.Fatalf("decode before rules: %v", err)
	}

	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/providers/"+strconv.FormatInt(provider.ID, 10)+"/packages/provider-pack/preview", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview provider package status = %d body=%s", rec.Code, rec.Body.String())
	}
	var previewResponse struct {
		Item model.RulePackagePreview `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&previewResponse); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if previewResponse.Item.ProviderID != provider.ID || previewResponse.Item.ProviderPackageRef != "provider-pack@v1" || len(previewResponse.Item.Added) != 1 {
		t.Fatalf("unexpected provider preview: %+v", previewResponse.Item)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list rules after preview status = %d body=%s", rec.Code, rec.Body.String())
	}
	var afterPreviewRules struct {
		Items []model.Rule `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&afterPreviewRules); err != nil {
		t.Fatalf("decode after preview rules: %v", err)
	}
	if len(afterPreviewRules.Items) != len(beforeRules.Items) {
		t.Fatalf("provider preview mutated rules: before=%d after=%d", len(beforeRules.Items), len(afterPreviewRules.Items))
	}

	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/providers/"+strconv.FormatInt(provider.ID, 10)+"/packages/provider-pack/import", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("import provider package status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list rules after import status = %d body=%s", rec.Code, rec.Body.String())
	}
	var importedRules struct {
		Items []model.Rule `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&importedRules); err != nil {
		t.Fatalf("decode imported rules: %v", err)
	}
	var imported model.Rule
	for _, rule := range importedRules.Items {
		if rule.PackageID == "provider-pack" {
			imported = rule
			break
		}
	}
	if imported.ID == 0 || imported.ProviderID != provider.ID || imported.ProviderName != "Provider feed" || imported.ProviderPackageRef != "provider-pack@v1" {
		t.Fatalf("expected imported provider lineage, got %+v", imported)
	}

	readonlyToken, _, err := auth.IssueToken("test-secret", "readonly", 99, "readonly", 3600000000000)
	if err != nil {
		t.Fatalf("issue readonly token: %v", err)
	}
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/providers/"+strconv.FormatInt(provider.ID, 10)+"/sync", nil), readonlyToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly provider sync status = %d body=%s", rec.Code, rec.Body.String())
	}

	failedProviderBody := `{"name":"Denied feed","provider_type":"https-catalog","endpoint":"https://unauthorized.example.com/catalog.json","auth_mode":"none","enabled":true,"timeout_sec":1,"retry_policy":{"max_attempts":1,"backoff_sec":1}}`
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/providers", bytes.NewBufferString(failedProviderBody)), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create failed provider status = %d body=%s", rec.Code, rec.Body.String())
	}
	var failedProviderResponse struct {
		Item model.RuleProviderAdapter `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&failedProviderResponse); err != nil {
		t.Fatalf("decode failed provider: %v", err)
	}
	req = withToken(httptest.NewRequest(http.MethodPost, "/api/v1/rule-community/providers/"+strconv.FormatInt(failedProviderResponse.Item.ID, 10)+"/retry", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("retry denied provider status = %d body=%s", rec.Code, rec.Body.String())
	}
	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/rule-community/providers/"+strconv.FormatInt(failedProviderResponse.Item.ID, 10), nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get denied provider status = %d body=%s", rec.Code, rec.Body.String())
	}
	var deniedDetail struct {
		Item model.RuleProviderAdapter `json:"item"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&deniedDetail); err != nil {
		t.Fatalf("decode denied provider detail: %v", err)
	}
	if deniedDetail.Item.HealthStatus != "unauthorized" || !deniedDetail.Item.RetryExhausted {
		t.Fatalf("expected unauthorized exhausted provider, got %+v", deniedDetail.Item)
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil), token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list rules after failed retry status = %d body=%s", rec.Code, rec.Body.String())
	}
	var afterFailedRetryRules struct {
		Items []model.Rule `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&afterFailedRetryRules); err != nil {
		t.Fatalf("decode after failed retry rules: %v", err)
	}
	if len(afterFailedRetryRules.Items) != len(importedRules.Items) {
		t.Fatalf("failed provider retry mutated rules: before=%d after=%d", len(importedRules.Items), len(afterFailedRetryRules.Items))
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

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/waf-events", bytes.NewBufferString(`{"request_id":"req-bot","site_id":1,"event_type":"bot-protection","rule_id":11,"rule_type":"challenge","target":"path","module":"bot-protection","category":"challenge","rule_name":"Admin challenge","challenge_mode":"captcha","challenge_result":"failed","bot_result":"captcha-failed","bot_reason":"answer mismatch","device_signal":"matched","action":"block","disposition":"blocked","client_ip":"192.0.2.50","method":"GET","uri":"/admin","summary":"challenge failed"}`))
	req.Header.Set("Authorization", "Bearer gateway-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("ingest bot protection waf status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = withToken(httptest.NewRequest(http.MethodGet, "/api/v1/attack-logs?module=bot-protection&challenge_result=failed&bot_result=captcha-failed", nil), token)
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
	if len(attackResponse.Items) != 1 || attackResponse.Items[0].Module != "bot-protection" || attackResponse.Items[0].ChallengeResult != "failed" || attackResponse.Items[0].BotResult != "captcha-failed" {
		t.Fatalf("unexpected bot protection logs: %+v", attackResponse.Items)
	}
	if attackResponse.Items[0].BotReason != "answer mismatch" || attackResponse.Items[0].DeviceSignal != "matched" {
		t.Fatalf("unexpected bot protection enhancement fields: %+v", attackResponse.Items[0])
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
	if len(summaryResponse.Item.BotProtection) != 1 || summaryResponse.Item.BotProtection[0].Key != "failed|captcha-failed|block|blocked" {
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

func moduleExists(items []model.ProtectionModuleOverview, key string) bool {
	for _, item := range items {
		if item.Key == key {
			return true
		}
	}
	return false
}

func assertNoCertificateMaterial(t *testing.T, body string, certPEM string, keyPEM string) {
	t.Helper()
	for _, leaked := range []string{
		strings.TrimSpace(certPEM),
		strings.TrimSpace(keyPEM),
		"BEGIN CERTIFICATE",
		"BEGIN RSA PRIVATE KEY",
		"BEGIN PRIVATE KEY",
		"PRIVATE KEY",
	} {
		if leaked != "" && strings.Contains(body, leaked) {
			t.Fatalf("response leaked certificate material %q in body: %s", leaked, body)
		}
	}
}

func testHTTPServerCertificatePEM(t *testing.T, dnsName string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPEM, keyPEM
}
