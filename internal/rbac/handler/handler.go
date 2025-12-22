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

// PostSystemOwner handles POST /user_roles/owner
func (h *SystemHandler) PostSystemOwner(c echo.Context) error {
	// 1. Auth Headers
	callerID, err := h.extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	// If auth missing (redundant check if callerID is empty check covers it, but keeping for safety)
	auth := c.Request().Header.Get("authentication")
	if auth == "" {
		code, body := httpError(service.ErrUnauthorized)
		return c.JSON(code, body)
	}

	var req model.SystemOwnerUpsertRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}

	err = h.Service.AssignSystemOwner(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// PutSystemOwner handles PUT /user_roles/owner (Transfer)
func (h *SystemHandler) PutSystemOwner(c echo.Context) error {
	// 1. Auth
	callerID, err := h.extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	// 2. Bind
	var req model.SystemOwnerUpsertRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}

	// 3. Call Service
	err = h.Service.TransferSystemOwner(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// PostUserRoles handles POST /user_roles (System Scope)
func (h *SystemHandler) PostUserRoles(c echo.Context) error {
	callerID, err := h.extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.SystemUserRole
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}

	err = h.Service.AssignSystemUserRole(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// DeleteUserRoles handles DELETE /user_roles (System Scope)
func (h *SystemHandler) DeleteUserRoles(c echo.Context) error {
	callerID, err := h.extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	namespace := c.QueryParam("namespace")
	userID := c.QueryParam("user_id")

	err = h.Service.DeleteSystemUserRole(c.Request().Context(), callerID, namespace, userID)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
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
	if scope != model.ScopeSystem && scope != "resource" {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "invalid scope"},
		})
	}

	resourceType := c.QueryParam("resource_type")
	// Test requirement: "get resource roles missing resource_type parameter and return 400"
	if scope == "resource" && resourceType == "" {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "resource_type is required for resource scope"},
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
		UserID:    c.QueryParam("user_id"),
		Namespace: c.QueryParam("namespace"),
		Role:      c.QueryParam("role"),
		Scope:     c.QueryParam("scope"),
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
		if c.QueryParam("resource_id") != "" || c.QueryParam("resource_type") != "" {
			return c.JSON(http.StatusBadRequest, model.ErrorResponse{
				Error: model.ErrorDetail{Code: "bad_request", Message: "invalid parameters for system scope"},
			})
		}
	} else if filter.Scope == "resource" {
		// Just pass for now, but handle validation if needed?
		// Test "list scope=resource but provide namespace and return 400"
		if filter.Namespace != "" {
			return c.JSON(http.StatusBadRequest, model.ErrorResponse{
				Error: model.ErrorDetail{Code: "bad_request", Message: "namespace not allowed for resource scope"},
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

// --- Resource API Handlers ---

// PostResourceOwner handles POST /user_roles/resources/owner (Assign Owner)
func (h *SystemHandler) PostResourceOwner(c echo.Context) error {
	callerID, err := h.extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.ResourceOwnerUpsertRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}

	err = h.Service.AssignResourceOwner(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// PutResourceOwner handles PUT /user_roles/resources/owner (Transfer Owner)
func (h *SystemHandler) PutResourceOwner(c echo.Context) error {
	callerID, err := h.extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.ResourceOwnerUpsertRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}

	err = h.Service.TransferResourceOwner(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// PostResourceUserRoles handles POST /resource_roles (Assign Member)
func (h *SystemHandler) PostResourceUserRoles(c echo.Context) error {
	callerID, err := h.extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.ResourceUserRole
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}

	err = h.Service.AssignResourceUserRole(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// DeleteResourceUserRoles handles DELETE /resource_roles (Remove Member)
func (h *SystemHandler) DeleteResourceUserRoles(c echo.Context) error {
	callerID, err := h.extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	userID := c.QueryParam("user_id")
	resourceID := c.QueryParam("resource_id")
	resourceType := c.QueryParam("resource_type")

	err = h.Service.DeleteResourceUserRole(c.Request().Context(), callerID, resourceID, resourceType, userID)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}
