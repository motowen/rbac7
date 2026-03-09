package router

import (
	"rbac7/internal/rbac/handler"
	"rbac7/internal/rbac/identity"
	"rbac7/internal/rbac/policy"
	"rbac7/internal/rbac/repository"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func RegisterRoutes(e *echo.Echo, h *handler.SystemHandler, policyEngine *policy.Engine, repo repository.RBACRepository, apiConfigs map[string][]*policy.APIConfig) {
	RegisterRoutesWithVerifier(e, h, policyEngine, repo, apiConfigs, nil)
}

func RegisterRoutesWithVerifier(e *echo.Echo, h *handler.SystemHandler, policyEngine *policy.Engine, repo repository.RBACRepository, apiConfigs map[string][]*policy.APIConfig, verifier identity.TokenVerifier) {
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{echo.GET, echo.PUT, echo.POST, echo.DELETE, echo.OPTIONS},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization, "authentication", "x-user-id"},
	}))

	e.File("/docs/rbac.yaml", "docs/rbac.yaml")
	e.GET("/health", handler.HealthCheck)

	v1 := e.Group("/api/v1")
	v1.Use(handler.RequestIDMiddleware)

	v1.POST("/permissions/check", h.PostPermissionsCheck)
	v1.POST("/permissions/check/batch", h.PostPermissionsCheckBatch)

	rbacMiddleware := handler.NewRBACMiddlewareWithVerifier(policyEngine, repo, apiConfigs, verifier)
	v1.Use(rbacMiddleware.Middleware())

	v1.POST("/user_roles/owner", h.PostSystemOwner)
	v1.PUT("/user_roles/owner", h.PutSystemOwner)
	v1.POST("/user_roles", h.PostUserRoles)
	v1.POST("/user_roles/batch", h.PostUserRolesBatch)
	v1.DELETE("/user_roles", h.DeleteUserRoles)
	v1.GET("/user_roles/me", h.GetUserRolesMe)
	v1.GET("/user_roles", h.GetUserRoles)
	v1.GET("/user_roles/logs", h.GetUserRoleHistory)

	v1.POST("/user_roles/resources/owner", h.PostResourceOwner)
	v1.PUT("/user_roles/resources/owner", h.PutResourceOwner)
	v1.POST("/user_roles/resources", h.PostResourceUserRoles)
	v1.POST("/user_roles/resources/batch", h.PostResourceUserRolesBatch)
	v1.DELETE("/user_roles/resources", h.DeleteResourceUserRoles)

	v1.PUT("/resources/delete", h.PutDeleteResource)
	v1.POST("/resources/dashboards", h.GetDashboardResource)
}
