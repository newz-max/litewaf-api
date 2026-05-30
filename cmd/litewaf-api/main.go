package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"litewaf-api/internal/app"
	"litewaf-api/internal/config"
	"litewaf-api/internal/httpserver"
	"litewaf-api/internal/store"
)

func main() {
	cfg := config.Load()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dataStore := store.Store(store.NewMemoryStore())
	if cfg.DatabaseURL != "" {
		pgStore, err := store.OpenPostgres(ctx, cfg.DatabaseURL)
		if err != nil {
			logger.Error("database connection failed", "error", err)
			os.Exit(1)
		}
		dataStore = pgStore
		logger.Info("database connected", "driver", "postgres")
	} else {
		logger.Warn("DATABASE_URL is empty, using in-memory store")
	}
	defer dataStore.Close()

	application := app.New(cfg, dataStore)
	server := httpserver.New(cfg, logger, application)

	errCh := make(chan error, 1)
	go func() {
		logger.Info("litewaf api started", "addr", cfg.HTTPAddr, "env", cfg.Env)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		logger.Error("server failed", "error", err)
		os.Exit(1)
	case sig := <-stopCh:
		logger.Info("shutdown signal received", "signal", sig.String())
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("server shutdown failed", "error", err)
		os.Exit(1)
	}

	logger.Info("litewaf api stopped")
}
