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

// PostSystemOwner handles POST /user_roles/owner
func (h *SystemHandler) PostSystemOwner(c echo.Context) error {
	// 1. Auth Headers
	callerID := c.Request().Header.Get("x-user-id")
	if callerID == "" {
		code, body := httpError(service.ErrUnauthorized)
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

	err := h.Service.AssignSystemOwner(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}
