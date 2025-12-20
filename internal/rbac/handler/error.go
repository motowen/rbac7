package handler

import (
	"net/http"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/service"
)

// Helper to map errors to HTTP status and body
func httpError(err error) (int, interface{}) {
	var code string
	var msg string
	var status int

	switch err {
	case service.ErrForbidden:
		status = http.StatusForbidden
		code = "forbidden"
		msg = "Permission denied"
	case service.ErrConflict:
		status = http.StatusConflict
		code = "conflict"
		msg = "System owner or role already exists"
	case service.ErrInvalidNamespace:
		status = http.StatusBadRequest
		code = "bad_request"
		msg = "Namespace required"
	case service.ErrBadRequest:
		status = http.StatusBadRequest
		code = "bad_request"
		msg = "Invalid input"
	case service.ErrUnauthorized:
		status = http.StatusUnauthorized
		code = "unauthorized"
		msg = "Unauthorized"
	default:
		status = http.StatusInternalServerError
		code = "internal_error"
		msg = err.Error()
	}

	return status, model.ErrorResponse{
		Error: model.ErrorDetail{Code: code, Message: msg},
	}
}
