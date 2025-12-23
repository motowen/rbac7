package handler

import (
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
