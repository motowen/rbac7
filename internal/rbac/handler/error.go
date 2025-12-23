package handler

import (
	"errors"
	"net/http"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/service"
)

// Helper to map errors to HTTP status and body
func httpError(err error) (int, interface{}) {
	if errors.Is(err, service.ErrUnauthorized) {
		return http.StatusUnauthorized, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "unauthorized", Message: err.Error()},
		}
	}
	if errors.Is(err, service.ErrForbidden) {
		return http.StatusForbidden, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "forbidden", Message: err.Error()},
		}
	}
	if errors.Is(err, service.ErrConflict) {
		return http.StatusConflict, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "conflict", Message: err.Error()},
		}
	}
	if errors.Is(err, service.ErrInvalidNamespace) || errors.Is(err, service.ErrBadRequest) {
		return http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: err.Error()},
		}
	}

	// Fallback
	return http.StatusInternalServerError, model.ErrorResponse{
		Error: model.ErrorDetail{Code: "internal_error", Message: "Internal Server Error"},
	}
}
