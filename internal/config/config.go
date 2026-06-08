package config

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AppName                string
	Env                    string
	HTTPAddr               string
	LogLevel               slog.Level
	DatabaseURL            string
	RedisAddr              string
	GatewayConfigPath      string
	GatewayReloadCommand   string
	GatewayListenerMode    string
	GatewayBridgePortRange string
	PublishOperator        string
	AuthTokenSecret        string
	AuthTokenTTL           time.Duration
	AdminUsername          string
	AdminPassword          string
	AdminRole              string
	GatewayIngestionToken  string
	MetricsEnabled         bool
	GeoIPDatabasePath      string
	GeoIPCacheSize         int
}

func Load() Config {
	return Config{
		AppName:     getEnv("APP_NAME", "LiteWaf API"),
		Env:         getEnv("APP_ENV", "dev"),
		HTTPAddr:    getEnv("HTTP_ADDR", ":8080"),
		LogLevel:    parseLogLevel(getEnv("LOG_LEVEL", "info")),
		DatabaseURL: getEnv("DATABASE_URL", ""),
		RedisAddr:   getEnv("REDIS_ADDR", ""),
		GatewayConfigPath: getEnv(
			"GATEWAY_CONFIG_PATH",
			"/var/lib/litewaf/gateway/active.json",
		),
		GatewayReloadCommand:   getEnv("GATEWAY_RELOAD_COMMAND", ""),
		GatewayListenerMode:    normalizeGatewayListenerMode(getEnv("GATEWAY_LISTENER_MODE", "host-network")),
		GatewayBridgePortRange: getEnv("GATEWAY_BRIDGE_PORT_RANGE", ""),
		PublishOperator:        getEnv("PUBLISH_OPERATOR", "system"),
		AuthTokenSecret:        getEnv("AUTH_TOKEN_SECRET", "dev-litewaf-change-me"),
		AuthTokenTTL:           getEnvDuration("AUTH_TOKEN_TTL_MINUTES", 12*time.Hour),
		AdminUsername:          getEnv("LITEWAF_ADMIN_USERNAME", "admin"),
		AdminPassword:          getEnv("LITEWAF_ADMIN_PASSWORD", "admin123456"),
		AdminRole:              getEnv("LITEWAF_ADMIN_ROLE", "admin"),
		GatewayIngestionToken:  getEnv("GATEWAY_INGESTION_TOKEN", ""),
		MetricsEnabled:         getEnvBool("METRICS_ENABLED", false),
		GeoIPDatabasePath:      getEnv("LITEWAF_GEOIP_DB_PATH", ""),
		GeoIPCacheSize:         getEnvInt("LITEWAF_GEOIP_CACHE_SIZE", 2048),
	}
}

func (c Config) ValidateProduction() error {
	if strings.ToLower(strings.TrimSpace(c.Env)) != "production" {
		return nil
	}

	var unsafe []string
	if isUnsafeSecret(c.AuthTokenSecret) {
		unsafe = append(unsafe, "AUTH_TOKEN_SECRET")
	}
	if isUnsafeSecret(c.GatewayIngestionToken) {
		unsafe = append(unsafe, "GATEWAY_INGESTION_TOKEN")
	}
	if isUnsafeSecret(c.AdminPassword) {
		unsafe = append(unsafe, "LITEWAF_ADMIN_PASSWORD")
	}
	if isUnsafeDatabaseURL(c.DatabaseURL) {
		unsafe = append(unsafe, "DATABASE_URL")
	}
	if len(unsafe) > 0 {
		return fmt.Errorf("unsafe production configuration: %s", strings.Join(unsafe, ", "))
	}
	return nil
}

func getEnv(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	minutes, err := strconv.Atoi(value)
	if err != nil || minutes <= 0 {
		return fallback
	}
	return time.Duration(minutes) * time.Minute
}

func getEnvBool(key string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if value == "" {
		return fallback
	}
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func getEnvInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return fallback
	}
	return parsed
}

func normalizeGatewayListenerMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "bridge", "bridge-range", "fixed-range", "fixed-port-range":
		return "bridge-range"
	case "host", "host-network", "host_network":
		return "host-network"
	default:
		return "host-network"
	}
}

func parseLogLevel(value string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func isUnsafeSecret(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "change-me", "admin123456", "litewaf_dev_password", "dev-litewaf-change-me", "dev-gateway-change-me":
		return true
	default:
		return false
	}
}

func isUnsafeDatabaseURL(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return true
	}
	password, ok := parsed.User.Password()
	if !ok {
		return true
	}
	return isUnsafeSecret(password)
}
