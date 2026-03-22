package handler

import (
	"errors"
	"net/http"
	"rbac7/internal/abac/model"
	"rbac7/internal/abac/service"
)

// httpError maps service errors to HTTP status codes and error responses
func httpError(err error) (int, model.ErrorResponse) {
	switch {
	case errors.Is(err, service.ErrUnauthorized):
		return http.StatusUnauthorized, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "unauthorized", Message: "Authentication required"},
		}
	case errors.Is(err, service.ErrForbidden):
		return http.StatusForbidden, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "forbidden", Message: "Insufficient permissions"},
		}
	case errors.Is(err, service.ErrBadRequest):
		return http.StatusBadRequest, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "bad_request", Message: err.Error()},
		}
	case errors.Is(err, service.ErrNotFound):
		return http.StatusNotFound, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "not_found", Message: "Resource not found"},
		}
	case errors.Is(err, service.ErrConflict):
		return http.StatusConflict, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "conflict", Message: err.Error()},
		}
	default:
		return http.StatusInternalServerError, model.ErrorResponse{
			Error: model.ErrorDetail{Code: "internal_error", Message: "Internal server error"},
		}
	}
}

// validationError creates a validation error response
func validationError(err error) model.ErrorResponse {
	return model.ErrorResponse{
		Error: model.ErrorDetail{Code: "validation_error", Message: err.Error()},
	}
}
