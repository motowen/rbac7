package router

import (
	"rbac7/internal/rbac/handler"
	"rbac7/internal/rbac/policy"
	"rbac7/internal/rbac/repository"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func RegisterRoutes(e *echo.Echo, h *handler.SystemHandler, policyEngine *policy.Engine, repo repository.RBACRepository, apiConfigs map[string][]*policy.APIConfig) {
	// Enable CORS for Swagger UI interaction
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{echo.GET, echo.PUT, echo.POST, echo.DELETE, echo.OPTIONS},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, "authentication", "x-user-id"},
	}))

	// Serve Swagger Spec
	e.File("/docs/rbac.yaml", "docs/rbac.yaml")

	// Health Check
	e.GET("/health", handler.HealthCheck)

	// Prefix from rbac.yaml: /api/v1
	v1 := e.Group("/api/v1")
	v1.Use(handler.RequestIDMiddleware) // Add Request ID middleware to API routes

	// Permissions check endpoint - NO RBAC middleware (anyone can check permissions)
	v1.POST("/permissions/check", h.PostPermissionsCheck)

	// Create and apply RBAC middleware for protected routes
	rbacMiddleware := handler.NewRBACMiddleware(policyEngine, repo, apiConfigs)
	v1.Use(rbacMiddleware.Middleware())

	// System Scope Routes
	v1.POST("/user_roles/owner", h.PostSystemOwner)
	v1.PUT("/user_roles/owner", h.PutSystemOwner)
	v1.POST("/user_roles", h.PostUserRoles)
	v1.POST("/user_roles/batch", h.PostUserRolesBatch)
	v1.DELETE("/user_roles", h.DeleteUserRoles)
	v1.GET("/user_roles/me", h.GetUserRolesMe)
	v1.GET("/user_roles", h.GetUserRoles)
	v1.GET("/user_roles/logs", h.GetUserRoleHistory) // History logs for both system and resource scope

	// Resource Scope Routes
	v1.POST("/user_roles/resources/owner", h.PostResourceOwner)
	v1.PUT("/user_roles/resources/owner", h.PutResourceOwner)
	v1.POST("/user_roles/resources", h.PostResourceUserRoles)
	v1.POST("/user_roles/resources/batch", h.PostResourceUserRolesBatch)
	v1.DELETE("/user_roles/resources", h.DeleteResourceUserRoles)

	// Resource Management Routes
	v1.PUT("/resources/delete", h.PutDeleteResource)
	v1.POST("/resources/dashboards", h.GetDashboardResource)
}
