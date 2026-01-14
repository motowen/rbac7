package handler

import (
	"net/http"
	"rbac7/internal/rbac/model"

	"github.com/labstack/echo/v4"
)

// PostLibraryWidgetViewers handles POST /user_roles/library_widgets/batch
func (h *SystemHandler) PostLibraryWidgetViewers(c echo.Context) error {
	callerID, err := h.extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.AssignLibraryWidgetViewersReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid body"},
		})
	}

	if err := req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, validationError(err))
	}

	result, err := h.Service.AssignLibraryWidgetViewers(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, result)
}

// DeleteLibraryWidgetViewer handles DELETE /user_roles/library_widgets
func (h *SystemHandler) DeleteLibraryWidgetViewer(c echo.Context) error {
	callerID, err := h.extractCallerID(c)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	var req model.DeleteLibraryWidgetViewerReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: "Invalid parameters"},
		})
	}

	if err := req.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, validationError(err))
	}

	err = h.Service.DeleteLibraryWidgetViewer(c.Request().Context(), callerID, req)
	if err != nil {
		code, body := httpError(err)
		return c.JSON(code, body)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success"})
}
