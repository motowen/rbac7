package nats

import (
	"errors"
	"rbac7/internal/rbac/service"
)

func MapErrorCode(err error) Code {
	switch {
	case errors.Is(err, service.ErrUnauthorized):
		return CodeUnauthorized
	case errors.Is(err, service.ErrForbidden):
		return CodeForbidden
	case errors.Is(err, service.ErrInvalidNamespace), errors.Is(err, service.ErrBadRequest):
		return CodeBadRequest
	default:
		return CodeInternalError
	}
}
