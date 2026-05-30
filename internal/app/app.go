package app

import "litewaf-api/internal/config"

const Version = "0.1.0"

type App struct {
	Config config.Config
}

func New(cfg config.Config) *App {
	return &App{
		Config: cfg,
	}
}
