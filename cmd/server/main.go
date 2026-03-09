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
	"rbac7/internal/rbac/identity"
	"rbac7/internal/rbac/repository"
	"rbac7/internal/rbac/router"
	"rbac7/internal/rbac/service"
	rbacnats "rbac7/internal/rbac/transport/nats"
	"rbac7/internal/rbac/util"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	gonats "github.com/nats-io/nats.go"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	util.InitLogger()
	logger := util.GetLogger()

	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.MongoURI))
	if err != nil {
		logger.Error("Failed to connect to MongoDB", "error", err)
		os.Exit(1)
	}

	db := client.Database(cfg.DBName)
	repo := repository.NewMongoRepository(db, cfg.UserRolesCollection, cfg.ResourceRolesCollection)
	orgUserRepo := repository.NewMongoOrgUserRepository(db, cfg.OrgUsersCollection)

	if err := repo.EnsureIndexes(context.Background()); err != nil {
		logger.Warn("Failed to ensure indexes", "error", err)
	}
	if err := repo.EnsureHistoryIndexes(context.Background()); err != nil {
		logger.Warn("Failed to ensure history indexes", "error", err)
	}

	svc := service.NewServiceWithOrg(repo, repo, orgUserRepo)
	keySource := identity.NewRemoteJWKSKeySource(cfg.JWT.JWKSURL, http.DefaultClient)
	verifier := identity.NewJWTVerifier(cfg.JWT, keySource)
	h := handler.NewSystemHandlerWithVerifier(svc, verifier)

	var natsConn *gonats.Conn
	if cfg.NATS.URL != "" {
		natsConn, err = gonats.Connect(cfg.NATS.URL)
		if err != nil {
			logger.Error("Failed to connect to NATS", "error", err)
			os.Exit(1)
		}

		natsServer, err := rbacnats.NewServer(cfg.NATS, svc, verifier)
		if err != nil {
			logger.Error("Failed to initialize NATS RBAC server", "error", err)
			os.Exit(1)
		}
		if err := natsServer.Register(natsConn); err != nil {
			logger.Error("Failed to register NATS RBAC handlers", "error", err)
			os.Exit(1)
		}
	}

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

	policyLoader := svc.Policy.GetLoader()
	apiConfigs := policyLoader.LoadAPIConfigs(svc.Policy.GetEntityPolicies())

	router.RegisterRoutesWithVerifier(e, h, svc.Policy, repo, apiConfigs, verifier)

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      e,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	go func() {
		logger.Info("Starting server", "port", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("shutting down the server", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server Shutdown Failed", "error", err)
	}

	if natsConn != nil {
		natsConn.Drain()
		natsConn.Close()
	}

	if err := client.Disconnect(ctx); err != nil {
		logger.Error("Failed to disconnect DB", "error", err)
	}

	logger.Info("Server exited properly")
}
