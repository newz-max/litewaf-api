package config

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AppName               string
	Env                   string
	HTTPAddr              string
	LogLevel              slog.Level
	DatabaseURL           string
	RedisAddr             string
	GatewayConfigPath     string
	PublishOperator       string
	AuthTokenSecret       string
	AuthTokenTTL          time.Duration
	AdminUsername         string
	AdminPassword         string
	AdminRole             string
	GatewayIngestionToken string
	MetricsEnabled        bool
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
		PublishOperator:       getEnv("PUBLISH_OPERATOR", "system"),
		AuthTokenSecret:       getEnv("AUTH_TOKEN_SECRET", "dev-litewaf-change-me"),
		AuthTokenTTL:          getEnvDuration("AUTH_TOKEN_TTL_MINUTES", 12*time.Hour),
		AdminUsername:         getEnv("LITEWAF_ADMIN_USERNAME", "admin"),
		AdminPassword:         getEnv("LITEWAF_ADMIN_PASSWORD", "admin123456"),
		AdminRole:             getEnv("LITEWAF_ADMIN_ROLE", "admin"),
		GatewayIngestionToken: getEnv("GATEWAY_INGESTION_TOKEN", ""),
		MetricsEnabled:        getEnvBool("METRICS_ENABLED", false),
	}
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
