package handler

import (
	"net/http"
	"rbac7/internal/rbac/model"

	"github.com/labstack/echo/v4"
)

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
