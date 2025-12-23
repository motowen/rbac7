package util

import (
	"log/slog"
	"os"
)

var Logger *slog.Logger

func InitLogger() {
	// Default to JSON handler for production
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	Logger = slog.New(handler)
	slog.SetDefault(Logger)
}

func GetLogger() *slog.Logger {
	if Logger == nil {
		InitLogger()
	}
	return Logger
}
