package config

import "testing"

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
