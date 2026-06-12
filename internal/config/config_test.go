package config

import "testing"

func TestLoadReadsGatewayClientMaxBodySize(t *testing.T) {
	t.Setenv("LITEWAF_GATEWAY_CLIENT_MAX_BODY_SIZE", "512M")

	cfg := Load()
	if cfg.NormalizedGatewayClientMaxBodySize() != "512m" {
		t.Fatalf("unexpected gateway client max body size: %q", cfg.NormalizedGatewayClientMaxBodySize())
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid gateway client max body size: %v", err)
	}
}

func TestValidateRejectsInvalidGatewayClientMaxBodySize(t *testing.T) {
	cfg := Config{GatewayClientMaxBodySize: "50m; lua_code_cache off;"}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid gateway client max body size to fail")
	}
}

func TestValidateProductionRejectsUnsafeDefaults(t *testing.T) {
	cfg := Config{
		Env:                   "production",
		DatabaseURL:           "postgres://litewaf:litewaf_dev_password@postgres:5432/litewaf?sslmode=disable",
		AuthTokenSecret:       "dev-litewaf-change-me",
		AdminPassword:         "admin123456",
		GatewayIngestionToken: "change-me",
	}

	if err := cfg.ValidateProduction(); err == nil {
		t.Fatal("expected unsafe production configuration to fail")
	}
}

func TestValidateProductionAcceptsStrongValues(t *testing.T) {
	cfg := Config{
		Env:                   "production",
		DatabaseURL:           "postgres://litewaf:strong-db-password@postgres:5432/litewaf?sslmode=disable",
		AuthTokenSecret:       "strong-auth-token-secret",
		AdminPassword:         "strong-admin-password",
		GatewayIngestionToken: "strong-gateway-token",
	}

	if err := cfg.ValidateProduction(); err != nil {
		t.Fatalf("expected strong production configuration to pass: %v", err)
	}
}

func TestValidateProductionSkipsNonProduction(t *testing.T) {
	cfg := Config{
		Env:                   "dev",
		DatabaseURL:           "",
		AuthTokenSecret:       "dev-litewaf-change-me",
		AdminPassword:         "admin123456",
		GatewayIngestionToken: "",
	}

	if err := cfg.ValidateProduction(); err != nil {
		t.Fatalf("expected non-production configuration to skip validation: %v", err)
	}
}

func TestLoadReadsGeoIPConfiguration(t *testing.T) {
	t.Setenv("LITEWAF_GEOIP_DB_PATH", "/data/litewaf/geoip.csv")
	t.Setenv("LITEWAF_GEOIP_CHINA_DB_PATH", "/data/litewaf/ip2region_v4.xdb")
	t.Setenv("LITEWAF_GEOIP_CACHE_SIZE", "128")

	cfg := Load()
	if cfg.GeoIPDatabasePath != "/data/litewaf/geoip.csv" || cfg.GeoIPChinaDatabasePath != "/data/litewaf/ip2region_v4.xdb" || cfg.GeoIPCacheSize != 128 {
		t.Fatalf("unexpected geoip config: %+v", cfg)
	}
}
