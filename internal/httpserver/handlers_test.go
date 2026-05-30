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
	"litewaf-api/internal/config"
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
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	application := app.New(cfg, store.NewMemoryStore())
	mux := http.NewServeMux()
	registerRoutes(mux, logger, application)
	return mux
}

func TestSiteCRUD(t *testing.T) {
	handler := testServer(t)

	body := bytes.NewBufferString(`{"name":"Example","host":"example.test","upstream":"http://upstream:8080","mode":"protect"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sites", body)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sites", nil)
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
	body := bytes.NewBufferString(`{"name":"Bad","host":"","upstream":"nope","mode":"protect"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sites", body)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestNotFound(t *testing.T) {
	handler := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sites/404", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
}
