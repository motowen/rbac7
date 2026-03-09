package handler

import (
	"net/http"
	"rbac7/internal/rbac/identity"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/service"
	"strings"

	"github.com/labstack/echo/v4"
)

type SystemHandler struct {
	Service  service.RBACService
	Verifier identity.TokenVerifier
}

func NewSystemHandler(s service.RBACService) *SystemHandler {
	return &SystemHandler{Service: s}
}

func NewSystemHandlerWithVerifier(s service.RBACService, verifier identity.TokenVerifier) *SystemHandler {
	return &SystemHandler{Service: s, Verifier: verifier}
}

func (h *SystemHandler) extractCallerID(c echo.Context) (string, error) {
	if h.Verifier == nil {
		callerID := c.Request().Header.Get("x-user-id")
		if callerID == "" {
			return "", service.ErrUnauthorized
		}
		return callerID, nil
	}

	token, err := extractBearerToken(c)
	if err != nil {
		return "", err
	}

	caller, err := h.Verifier.VerifyToken(c.Request().Context(), token)
	if err != nil || caller.UserID == "" {
		return "", service.ErrUnauthorized
	}

	ctx := identity.WithCallerContext(c.Request().Context(), caller)
	c.SetRequest(c.Request().WithContext(ctx))
	return "", nil
}

func extractBearerToken(c echo.Context) (string, error) {
	authorization := strings.TrimSpace(c.Request().Header.Get(echo.HeaderAuthorization))
	if authorization == "" {
		return "", service.ErrUnauthorized
	}

	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", service.ErrUnauthorized
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", service.ErrUnauthorized
	}

	return token, nil
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
		return c.JSON(http.StatusBadRequest, validationError(err))
	}

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
		return c.JSON(http.StatusBadRequest, validationError(err))
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
		return c.JSON(http.StatusBadRequest, validationError(err))
	}

	allowed, err := h.Service.CheckPermission(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, model.CheckPermissionResponse{Allowed: allowed})
}

func (h *SystemHandler) PostPermissionsCheckBatch(c echo.Context) error {
	callerID, err := h.extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.BatchCheckPermissionReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}

	if err := req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, validationError(err))
	}

	results, err := h.Service.BatchCheckPermission(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, model.BatchCheckPermissionResponse{Results: results})
}

func (h *SystemHandler) GetUserRoleHistory(c echo.Context) error {
	callerID, err := h.extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.GetUserRoleHistoryReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid parameters"},
		})
	}

	if err := req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, validationError(err))
	}

	result, err := h.Service.GetUserRoleHistory(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, result)
}
