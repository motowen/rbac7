package router

import (
	"rbac7/internal/rbac/handler"

	"github.com/labstack/echo/v4"
)

func RegisterRoutes(e *echo.Echo, h *handler.SystemHandler) {
	// Prefix from rbac.yaml: /api/v1
	v1 := e.Group("/api/v1")

	// System Scope Routes
	v1.POST("/user_roles/owner", h.PostSystemOwner)
	v1.PUT("/user_roles/owner", h.PutSystemOwner)
	v1.POST("/user_roles", h.PostUserRoles)
	v1.DELETE("/user_roles", h.DeleteUserRoles)
}
