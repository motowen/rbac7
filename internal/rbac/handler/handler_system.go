package handler

import (
	"net/http"
	"rbac7/internal/rbac/model"

	"github.com/labstack/echo/v4"
)

// PostSystemOwner handles POST /user_roles/owner
func (h *SystemHandler) PostSystemOwner(c echo.Context) error {
	// 1. Auth Headers
	callerID, err := h.extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	// 2. Bind
	var req model.AssignSystemOwnerReq
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
	var req model.TransferSystemOwnerReq
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

	var req model.AssignSystemUserRoleReq
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

	err = h.Service.AssignSystemUserRole(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// DeleteUserRoles handles DELETE /user_roles (System Scope)
// DeleteUserRoles handles DELETE /user_roles (System Scope)
func (h *SystemHandler) DeleteUserRoles(c echo.Context) error {
	callerID, err := h.extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.DeleteSystemUserRoleReq
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

	err = h.Service.DeleteSystemUserRole(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}
