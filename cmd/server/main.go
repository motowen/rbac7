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
	"rbac7/internal/rbac/repository"
	"rbac7/internal/rbac/router"
	"rbac7/internal/rbac/service"
	"rbac7/internal/rbac/util"

	abacconfig "rbac7/internal/abac/config"
	abachandler "rbac7/internal/abac/handler"
	abacrepo "rbac7/internal/abac/repository"
	abacrouter "rbac7/internal/abac/router"
	abacservice "rbac7/internal/abac/service"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	// Note: Go 1.21+ uses "log/slog", but for compatibility check standard lib
)

// Using standard lib "log/slog" if Go 1.21+, else adapter.
// Since go.mod says 1.24.6, we use "log/slog" inside util, but here we just call util.

func main() {
	// 0. Init Logger
	util.InitLogger()
	logger := util.GetLogger()

	// 1. Load Config (RBAC)
	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	// 1.1 Load Config (ABAC)
	abacCfg, err := abacconfig.LoadConfig()
	if err != nil {
		logger.Error("Failed to load ABAC config", "error", err)
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

	// 3. Init Layers (RBAC)
	db := client.Database(cfg.DBName)
	repo := repository.NewMongoRepository(db, cfg.UserRolesCollection, cfg.ResourceRolesCollection)
	orgUserRepo := repository.NewMongoOrgUserRepository(db, cfg.OrgUsersCollection)

	// Ensure Indexes
	if err := repo.EnsureIndexes(context.Background()); err != nil {
		logger.Warn("Failed to ensure indexes", "error", err)
		// Non-fatal?
	}
	if err := repo.EnsureHistoryIndexes(context.Background()); err != nil {
		logger.Warn("Failed to ensure history indexes", "error", err)
	}

	svc := service.NewServiceWithOrg(repo, repo, orgUserRepo) // repo implements both RBACRepository and HistoryRepository
	h := handler.NewSystemHandler(svc)

	// 3.1 Init Layers (ABAC)
	abacDB := client.Database(abacCfg.DBName)
	abacSubjectRepo := abacrepo.NewMongoABACRepository(abacDB, abacCfg.SubjectsCollection)
	abacPolicyRepo := abacrepo.NewMongoPolicyRepository(abacDB, abacCfg.PolicyRulesCollection, abacCfg.AttributeDefsCollection)

	// Ensure ABAC Indexes
	if err := abacSubjectRepo.EnsureIndexes(context.Background()); err != nil {
		logger.Warn("Failed to ensure ABAC subject indexes", "error", err)
	}
	if err := abacPolicyRepo.EnsureIndexes(context.Background()); err != nil {
		logger.Warn("Failed to ensure ABAC policy indexes", "error", err)
	}

	abacSvc, err := abacservice.NewService(abacSubjectRepo, abacPolicyRepo)
	if err != nil {
		logger.Error("Failed to init ABAC service", "error", err)
		os.Exit(1)
	}
	abacH := abachandler.NewHandler(abacSvc)

	// 4. Init Echo & Routes
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
	abacrouter.RegisterRoutes(e, abacH)

	// 5. Start Server with Graceful Shutdown
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

	// Wait for interrupt signal to gracefully shutdown the server with a timeout of 10 seconds.
	// Use a buffered channel to avoid missing signals as recommended for signal.Notify
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

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
