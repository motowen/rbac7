package router

import (
	"rbac7/internal/abac/handler"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// RegisterRoutes registers all ABAC routes
func RegisterRoutes(e *echo.Echo, h *handler.Handler) {
	// Enable CORS
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{echo.GET, echo.PUT, echo.POST, echo.DELETE, echo.OPTIONS},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, "x-user-id", "x-request-id"},
	}))

	// Health Check
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(200, map[string]string{"status": "ok"})
	})

	// API v1
	v1 := e.Group("/api/v1")
	v1.Use(handler.RequestIDMiddleware)

	// --- Public routes (access check) ---
	v1.POST("/access/check", h.PostCheckAccess)
	v1.POST("/access/check/batch", h.PostBatchCheckAccess)

	// --- Protected routes (require x-user-id header) ---

	// Subject CRUD
	v1.POST("/subjects", h.PostSubject)
	v1.GET("/subjects/:user_id", h.GetSubject)
	v1.PUT("/subjects/:user_id", h.PutSubject)
	v1.DELETE("/subjects/:user_id", h.DeleteSubject)

	// Subject Groups
	v1.POST("/subjects/:user_id/groups", h.PostSubjectGroup)
	v1.DELETE("/subjects/:user_id/groups/:group_id", h.DeleteSubjectGroup)

	// Subject Orgs
	v1.PUT("/subjects/:user_id/orgs", h.PutSubjectOrg)
	v1.DELETE("/subjects/:user_id/orgs/:org_id", h.DeleteSubjectOrg)

	// Policy Rules
	v1.POST("/policies", h.PostPolicyRule)
	v1.PUT("/policies/:rule_id", h.PutPolicyRule)
	v1.DELETE("/policies/:rule_id", h.DeletePolicyRule)
	v1.GET("/policies", h.GetPolicyRules)

	// Attribute Definitions
	v1.POST("/attributes", h.PostAttributeDefinition)
	v1.GET("/attributes", h.GetAttributeDefinitions)
	v1.DELETE("/attributes/:key", h.DeleteAttributeDefinition)
}
