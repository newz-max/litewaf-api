package svc

import (
	"log/slog"

	"litewaf-api/internal/app"
	"litewaf-api/internal/config"
	"litewaf-api/internal/store"
)

type ServiceContext struct {
	Config config.Config
	Logger *slog.Logger
	App    *app.App
	Store  store.Store
}

func NewServiceContext(logger *slog.Logger, application *app.App) *ServiceContext {
	return &ServiceContext{
		Config: application.Config,
		Logger: logger,
		App:    application,
		Store:  application.Store,
	}
}
