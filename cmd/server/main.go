package main

import (
	"context"
	"log"
	"time"

	"rbac7/internal/rbac/config"
	"rbac7/internal/rbac/handler"
	"rbac7/internal/rbac/repository"
	"rbac7/internal/rbac/router"
	"rbac7/internal/rbac/service"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	// 1. Load Config
	cfg := config.LoadConfig()

	// 2. Init MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.MongoURI))
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}
	defer func() {
		if err := client.Disconnect(context.Background()); err != nil {
			log.Printf("Failed to disconnect DB: %v", err)
		}
	}()

	db := client.Database(cfg.DBName)

	// 3. Init Layers
	repo := repository.NewMongoRepository(db, cfg.UserRolesCollection)

	// Ensure Indexes
	if err := repo.EnsureIndexes(context.Background()); err != nil {
		log.Printf("Warning: Failed to ensure indexes: %v", err)
	}

	svc := service.NewService(repo)
	h := handler.NewSystemHandler(svc)

	// 4. Init Echo & Routes
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	router.RegisterRoutes(e, h)

	// 5. Start Server
	log.Printf("Starting server on :%s", cfg.Port)
	if err := e.Start(":" + cfg.Port); err != nil {
		e.Logger.Fatal(err)
	}
}
