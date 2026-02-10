package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"system/internal/system/client"
	"system/internal/system/graph"
	"system/internal/system/repository"
	"system/internal/system/service"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	defaultPort = "7900"
	mongoURI    = "mongodb://localhost:27017"
	dbName      = "rbac_db"
	rbacBaseURL = "http://localhost:8080"
)

func main() {
	// MongoDB connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mongoClient, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}
	defer mongoClient.Disconnect(ctx)

	// Ping MongoDB
	if err := mongoClient.Ping(ctx, nil); err != nil {
		log.Fatal("Failed to ping MongoDB:", err)
	}
	log.Println("Connected to MongoDB")

	db := mongoClient.Database(dbName)
	repo := repository.NewMongoSystemRepository(db)
	widgetRepo := repository.NewMongoWidgetRepository(db)
	dashboardRepo := repository.NewMongoDashboardRepository(db)
	lockRepo := repository.NewMongoLockRepository(db)
	rbacClient := client.NewRBACClient(rbacBaseURL)

	// Initialize services
	entityService := service.NewEntityService(lockRepo)
	dashboardService := service.NewDashboardService(entityService, dashboardRepo, widgetRepo)
	widgetService := service.NewWidgetService(entityService, widgetRepo)

	// Ensure indexes
	ensureCtx, ensureCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer ensureCancel()
	if err := repo.EnsureIndexes(ensureCtx); err != nil {
		log.Println("Warning: failed to ensure system indexes:", err)
	}
	if err := widgetRepo.EnsureIndexes(ensureCtx); err != nil {
		log.Println("Warning: failed to ensure widget indexes:", err)
	}
	if err := dashboardRepo.EnsureIndexes(ensureCtx); err != nil {
		log.Println("Warning: failed to ensure dashboard indexes:", err)
	}
	if err := lockRepo.EnsureIndexes(ensureCtx); err != nil {
		log.Println("Warning: failed to ensure lock indexes:", err)
	}

	// Echo server
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	// GraphQL config with directive
	cfg := graph.Config{
		Resolvers: &graph.Resolver{
			Repo:             repo,
			WidgetRepo:       widgetRepo,
			DashboardRepo:    dashboardRepo,
			LockRepo:         lockRepo,
			RBACClient:       rbacClient,
			EntityService:    entityService,
			DashboardService: dashboardService,
			WidgetService:    widgetService,
		},
		Directives: graph.DirectiveRoot{
			Auth: graph.AuthDirective(rbacClient),
		},
	}

	// GraphQL handler
	srv := handler.NewDefaultServer(graph.NewExecutableSchema(cfg))

	// Middleware to pass echo context to GraphQL context
	e.POST("/graphql", func(c echo.Context) error {
		// Put echo context into request context
		ctx := context.WithValue(c.Request().Context(), "echo_context", c)
		c.SetRequest(c.Request().WithContext(ctx))
		srv.ServeHTTP(c.Response(), c.Request())
		return nil
	})

	// GraphQL Playground
	e.GET("/", func(c echo.Context) error {
		playground.Handler("GraphQL", "/graphql").ServeHTTP(c.Response(), c.Request())
		return nil
	})

	// Health check
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	log.Printf("System GraphQL server starting on http://localhost:%s", defaultPort)
	log.Printf("GraphQL Playground: http://localhost:%s/", defaultPort)
	log.Fatal(e.Start(":" + defaultPort))
}
