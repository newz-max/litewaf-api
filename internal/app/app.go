package app

import (
	"litewaf-api/internal/config"
	"litewaf-api/internal/store"
)

const Version = "0.1.0"

type App struct {
	Config config.Config
	Store  store.Store
}

func New(cfg config.Config, dataStore store.Store) *App {
	return &App{
		Config: cfg,
		Store:  dataStore,
	}
}
