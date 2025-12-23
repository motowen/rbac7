package router

import (
	"rbac7/internal/rbac/handler"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func RegisterRoutes(e *echo.Echo, h *handler.SystemHandler) {
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

	// System Scope Routes
	v1.POST("/user_roles/owner", h.PostSystemOwner)
	v1.PUT("/user_roles/owner", h.PutSystemOwner)
	v1.POST("/user_roles", h.PostUserRoles)
	v1.DELETE("/user_roles", h.DeleteUserRoles)
	v1.GET("/user_roles/me", h.GetUserRolesMe)
	v1.GET("/user_roles", h.GetUserRoles)

	// Resource Scope Routes
	v1.POST("/user_roles/resources/owner", h.PostResourceOwner)
	v1.PUT("/user_roles/resources/owner", h.PutResourceOwner)
	v1.POST("/user_roles/resources", h.PostResourceUserRoles)
	v1.DELETE("/user_roles/resources", h.DeleteResourceUserRoles)
	v1.POST("/permissions/check", h.PostPermissionsCheck)
}
