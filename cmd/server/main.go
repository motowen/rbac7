package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"rbac7/internal/rbac/config"
	"rbac7/internal/rbac/handler"
	natshandler "rbac7/internal/rbac/nats"
	"rbac7/internal/rbac/repository"
	"rbac7/internal/rbac/router"
	"rbac7/internal/rbac/service"
	"rbac7/internal/rbac/util"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/nats-io/nats.go"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	// 0. Init Logger
	util.InitLogger()
	logger := util.GetLogger()

	// 1. Load Config
	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	// 2. Init MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.MongoURI))
	if err != nil {
		logger.Error("Failed to connect to MongoDB", "error", err)
		os.Exit(1)
	}

	// 3. Init Layers
	db := client.Database(cfg.DBName)
	repo := repository.NewMongoRepository(db, cfg.UserRolesCollection, cfg.ResourceRolesCollection)
	orgUserRepo := repository.NewMongoOrgUserRepository(db, cfg.OrgUsersCollection)

	// Ensure Indexes
	if err := repo.EnsureIndexes(context.Background()); err != nil {
		logger.Warn("Failed to ensure indexes", "error", err)
		// Non-fatal
	}
	if err := repo.EnsureHistoryIndexes(context.Background()); err != nil {
		logger.Warn("Failed to ensure history indexes", "error", err)
	}

	svc := service.NewServiceWithOrg(repo, repo, orgUserRepo) // repo implements both RBACRepository and HistoryRepository
	h := handler.NewSystemHandler(svc)

	// 4. Init Echo & Routes (HTTP)
	e := echo.New()
	e.Use(middleware.Recover())
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogStatus: true,
		LogURI:    true,
		LogMethod: true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			logger.Info("request",
				"method", v.Method,
				"uri", v.URI,
				"status", v.Status,
			)
			return nil
		},
	}))

	// Load API configs for RBAC middleware
	policyLoader := svc.Policy.GetLoader()
	apiConfigs := policyLoader.LoadAPIConfigs(svc.Policy.GetEntityPolicies())

	router.RegisterRoutes(e, h, svc.Policy, repo, apiConfigs)

	// 5. Init NATS (Conditional)
	var nc *nats.Conn
	var authCallout *natshandler.AuthCalloutService
	var natsHandler *natshandler.NATSHandler

	if cfg.NATSEnabled {
		logger.Info("NATS is enabled, connecting...", "url", cfg.NATSURL)

		nc, err = nats.Connect(cfg.NATSURL,
			nats.UserInfo(cfg.NATSAuthUser, cfg.NATSAuthPassword),
			nats.MaxReconnects(-1),
			nats.ReconnectWait(2*time.Second),
			nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
				if err != nil {
					logger.Warn("NATS disconnected", "error", err)
				}
			}),
			nats.ReconnectHandler(func(nc *nats.Conn) {
				logger.Info("NATS reconnected", "url", nc.ConnectedUrl())
			}),
		)
		if err != nil {
			logger.Error("Failed to connect to NATS", "error", err)
			os.Exit(1)
		}
		logger.Info("Connected to NATS", "url", nc.ConnectedUrl())

		// Start Auth Callout Service
		authCallout, err = natshandler.NewAuthCalloutService(cfg, svc, nc)
		if err != nil {
			logger.Error("Failed to start NATS Auth Callout", "error", err)
			os.Exit(1)
		}

		// Register NATS Request-Reply Handlers
		natsHandler = natshandler.NewNATSHandler(nc, svc, svc.Policy, repo)
		if err := natsHandler.RegisterAll(); err != nil {
			logger.Error("Failed to register NATS handlers", "error", err)
			os.Exit(1)
		}
	}

	// 6. Start HTTP Server with Graceful Shutdown
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      e,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	go func() {
		logger.Info("Starting HTTP server", "port", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("shutting down the server", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server with a timeout of 10 seconds.
	// Use a buffered channel to avoid missing signals as recommended for signal.Notify
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Shutdown NATS
	if natsHandler != nil {
		natsHandler.UnsubscribeAll()
	}
	if authCallout != nil {
		if err := authCallout.Stop(); err != nil {
			logger.Error("Failed to stop Auth Callout", "error", err)
		}
	}
	if nc != nil {
		nc.Close()
		logger.Info("NATS connection closed")
	}

	// Shutdown Echo/Server
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server Shutdown Failed", "error", err)
	}

	// Disconnect DB
	if err := client.Disconnect(ctx); err != nil {
		logger.Error("Failed to disconnect DB", "error", err)
	}

	logger.Info("Server exited properly")
}
