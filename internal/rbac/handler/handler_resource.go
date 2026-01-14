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

	var req model.AssignResourceOwnerReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}

	if err := req.Validate(); err != nil {
		code, body := validationError(err)
		return c.JSON(code, body)
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

	var req model.TransferResourceOwnerReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}

	if err := req.Validate(); err != nil {
		code, body := validationError(err)
		return c.JSON(code, body)
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

	var req model.AssignResourceUserRoleReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}

	if err := req.Validate(); err != nil {
		code, body := validationError(err)
		return c.JSON(code, body)
	}

	err = h.Service.AssignResourceUserRole(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// DeleteResourceUserRoles handles DELETE /resource_roles (Remove Member)
// DeleteResourceUserRoles handles DELETE /resource_roles (Remove Member)
func (h *SystemHandler) DeleteResourceUserRoles(c echo.Context) error {
	callerID, err := h.extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.DeleteResourceUserRoleReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid parameters"},
		})
	}

	if err := req.Validate(); err != nil {
		code, body := validationError(err)
		return c.JSON(code, body)
	}

	err = h.Service.DeleteResourceUserRole(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// PostResourceUserRolesBatch handles POST /user_roles/resources/batch (Batch Assign Members)
func (h *SystemHandler) PostResourceUserRolesBatch(c echo.Context) error {
	callerID, err := h.extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.AssignResourceUserRolesReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}

	if err := req.Validate(); err != nil {
		code, body := validationError(err)
		return c.JSON(code, body)
	}

	result, err := h.Service.AssignResourceUserRoles(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, result)
}

// PutDeleteResource handles PUT /resources/delete (Soft Delete Resource)
func (h *SystemHandler) PutDeleteResource(c echo.Context) error {
	callerID, err := h.extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.SoftDeleteResourceReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}

	if err := req.Validate(); err != nil {
		code, body := validationError(err)
		return c.JSON(code, body)
	}

	err = h.Service.SoftDeleteResource(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}

// GetDashboardResource handles GET /resources/dashboards/:id
// Returns dashboard user roles and accessible widget IDs
func (h *SystemHandler) GetDashboardResource(c echo.Context) error {
	callerID, err := h.extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.GetDashboardResourceReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid parameters"},
		})
	}

	if err := req.Validate(); err != nil {
		code, body := validationError(err)
		return c.JSON(code, body)
	}

	result, err := h.Service.GetDashboardResource(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, result)
}
