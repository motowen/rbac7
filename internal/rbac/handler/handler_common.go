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

	var req model.GetUserRolesMeReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid parameters"},
		})
	}

	if err := req.Validate(); err != nil {
		// If err is *model.ErrorDetail, we can use it.
		if e, ok := err.(*model.ErrorDetail); ok {
			return c.JSON(http.StatusBadRequest, model.ErrorResponse{Error: *e})
		}
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: err.Error()},
		})
	}

	// Forward parameters to service
	roles, err := h.Service.GetUserRolesMe(c.Request().Context(), callerID, req)
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

	var req model.GetUserRolesReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid parameters"},
		})
	}

	if err := req.Validate(); err != nil {
		if e, ok := err.(*model.ErrorDetail); ok {
			return c.JSON(http.StatusBadRequest, model.ErrorResponse{Error: *e})
		}
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: err.Error()},
		})
	}

	roles, err := h.Service.GetUserRoles(c.Request().Context(), callerID, req)
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

	var req model.CheckPermissionReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}

	if err := req.Validate(); err != nil {
		if e, ok := err.(*model.ErrorDetail); ok {
			return c.JSON(http.StatusBadRequest, model.ErrorResponse{Error: *e})
		}
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: err.Error()},
		})
	}

	allowed, err := h.Service.CheckPermission(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, model.CheckPermissionResponse{Allowed: allowed})
}
