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
		AppName:           "LiteWaf API",
		Env:               "test",
		HTTPAddr:          ":0",
		GatewayConfigPath: t.TempDir() + "/active.json",
		PublishOperator:   "test",
		AuthTokenSecret:   "test-secret",
		AuthTokenTTL:      3600000000000,
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
