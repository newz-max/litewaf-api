package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"litewaf-api/internal/app"
	"litewaf-api/internal/config"
	"litewaf-api/internal/store"
	"litewaf-api/internal/svc"
)

type failingPingStore struct {
	store.Store
}

func (s failingPingStore) Ping(context.Context) error {
	return errors.New("database down")
}

func testServiceContext(dataStore store.Store) *svc.ServiceContext {
	cfg := config.Config{
		AppName:  "LiteWaf API",
		Env:      "test",
		HTTPAddr: ":0",
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	return svc.NewServiceContext(logger, app.New(cfg, dataStore))
}

func TestGoZeroHealthzCompatibleResponse(t *testing.T) {
	handler := HealthzHandler(testServiceContext(store.NewMemoryStore()))
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Status string `json:"status"`
		Time   string `json:"time"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Status != "ok" || response.Time == "" {
		t.Fatalf("unexpected health response: %+v", response)
	}
}

func TestGoZeroHealthzDegradedResponse(t *testing.T) {
	dataStore := failingPingStore{Store: store.NewMemoryStore()}
	handler := HealthzHandler(testServiceContext(dataStore))
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Time   string `json:"time"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Status != "degraded" || response.Error != "database unavailable" || response.Time == "" {
		t.Fatalf("unexpected degraded response: %+v", response)
	}
}

func TestGoZeroVersionCompatibleResponse(t *testing.T) {
	handler := VersionHandler(testServiceContext(store.NewMemoryStore()))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Name                     string `json:"name"`
		Version                  string `json:"version"`
		Env                      string `json:"env"`
		GatewayClientMaxBodySize string `json:"gateway_client_max_body_size"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Name != "LiteWaf API" || response.Version == "" || response.Env != "test" || response.GatewayClientMaxBodySize != "50m" {
		t.Fatalf("unexpected version response: %+v", response)
	}
}
