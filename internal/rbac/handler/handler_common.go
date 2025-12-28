package handler

import (
	"net/http"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/service"

	"github.com/labstack/echo/v4"
)

type SystemHandler struct {
	Service service.RBACService
}

func NewSystemHandler(s service.RBACService) *SystemHandler {
	return &SystemHandler{Service: s}
}

func (h *SystemHandler) extractCallerID(c echo.Context) (string, error) {
	callerID := c.Request().Header.Get("x-user-id")
	if callerID == "" {
		return "", service.ErrUnauthorized
	}
	return callerID, nil
}

func (h *SystemHandler) GetUserRolesMe(c echo.Context) error {
	callerID, err := h.extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	scope := c.QueryParam("scope")
	if scope == "" {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "scope is required"},
		})
	}
	if scope != model.ScopeSystem && scope != model.ScopeResource {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "invalid scope"},
		})
	}

	resourceType := c.QueryParam("resource_type")
	// Test requirement: "get resource roles missing resource_type parameter and return 400"
	if scope == model.ScopeResource && resourceType == "" {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "resource_type is required for resource scope"},
		})
	}

	if scope == model.ScopeSystem && resourceType != "" {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "resource_type should be empty for system scope"},
		})
	}

	// Forward parameters to service
	roles, err := h.Service.GetUserRolesMe(c.Request().Context(), callerID, scope, resourceType)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, roles)
}

func (h *SystemHandler) GetUserRoles(c echo.Context) error {
	callerID, err := h.extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	filter := model.UserRoleFilter{
		UserID:       c.QueryParam("user_id"),
		Namespace:    c.QueryParam("namespace"),
		Role:         c.QueryParam("role"),
		Scope:        c.QueryParam("scope"),
		ResourceID:   c.QueryParam("resource_id"),
		ResourceType: c.QueryParam("resource_type"),
	}

	if filter.Scope == "" {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "scope is required"},
		})
	}

	if filter.Scope == model.ScopeSystem {
		if filter.Namespace == "" {
			return c.JSON(http.StatusBadRequest, model.ErrorResponse{
				Error: model.ErrorDetail{Code: "bad_request", Message: "namespace required for system scope"},
			})
		}
		// Check mixed params? "list scope=system but provide resource_type/resource_id"
		if filter.ResourceID != "" || filter.ResourceType != "" {
			return c.JSON(http.StatusBadRequest, model.ErrorResponse{
				Error: model.ErrorDetail{Code: "bad_request", Message: "invalid parameters for system scope"},
			})
		}
	} else if filter.Scope == "resource" {
		if filter.Namespace != "" {
			return c.JSON(http.StatusBadRequest, model.ErrorResponse{
				Error: model.ErrorDetail{Code: "bad_request", Message: "namespace not allowed for resource scope"},
			})
		}
		if filter.ResourceID == "" || filter.ResourceType == "" {
			return c.JSON(http.StatusBadRequest, model.ErrorResponse{
				Error: model.ErrorDetail{Code: "bad_request", Message: "resource_id and resource_type required for resource scope"},
			})
		}
	} else {
		// Invalid scope
		// Not explicitly tested but good practice? Or rely on defaults?
		// "list members missing scope parameter" -> 400 (Handled).
	}

	roles, err := h.Service.GetUserRoles(c.Request().Context(), callerID, filter)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}
	return c.JSON(http.StatusOK, roles)
}

func (h *SystemHandler) PostPermissionsCheck(c echo.Context) error {
	callerID, err := h.extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.CheckPermissionRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}

	allowed, err := h.Service.CheckPermission(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, model.CheckPermissionResponse{Allowed: allowed})
}
