package config

import (
	"log/slog"
	"os"
	"strings"
)

type Config struct {
	AppName     string
	Env         string
	HTTPAddr    string
	LogLevel    slog.Level
	DatabaseURL string
	RedisAddr   string
}

func Load() Config {
	return Config{
		AppName:     getEnv("APP_NAME", "LiteWaf API"),
		Env:         getEnv("APP_ENV", "dev"),
		HTTPAddr:    getEnv("HTTP_ADDR", ":8080"),
		LogLevel:    parseLogLevel(getEnv("LOG_LEVEL", "info")),
		DatabaseURL: getEnv("DATABASE_URL", ""),
		RedisAddr:   getEnv("REDIS_ADDR", ""),
	}
}

func getEnv(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
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
