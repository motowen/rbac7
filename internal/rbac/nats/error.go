package natshandler

import (
	"encoding/json"

	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/service"
)

// natsError maps service errors to NATSError codes (mirrors HTTP handler/error.go).
func natsError(err error) *NATSError {
	switch {
	case err == nil:
		return nil
	case isError(err, service.ErrUnauthorized):
		return &NATSError{Code: "unauthorized", Message: err.Error()}
	case isError(err, service.ErrForbidden):
		return &NATSError{Code: "forbidden", Message: err.Error()}
	case isError(err, service.ErrConflict):
		return &NATSError{Code: "conflict", Message: err.Error()}
	case isError(err, service.ErrInvalidNamespace), isError(err, service.ErrBadRequest):
		return &NATSError{Code: "bad_request", Message: err.Error()}
	default:
		return &NATSError{Code: "internal_error", Message: "Internal Server Error"}
	}
}

func isError(err, target error) bool {
	return err.Error() == target.Error()
}

// validationNATSError converts validation errors to NATSError.
func validationNATSError(err error) *NATSError {
	var detail *model.ErrorDetail
	if asErrorDetail(err, &detail) {
		return &NATSError{Code: detail.Code, Message: detail.Message}
	}
	return &NATSError{Code: "bad_request", Message: err.Error()}
}

// asErrorDetail checks if err can be cast to *model.ErrorDetail.
func asErrorDetail(err error, target **model.ErrorDetail) bool {
	if e, ok := err.(*model.ErrorDetail); ok {
		*target = e
		return true
	}
	return false
}

// makeErrorResponse creates an error NATSResponse.
func makeErrorResponse(err *NATSError) []byte {
	resp := NATSResponse{
		Success: false,
		Error:   err,
	}
	data, _ := json.Marshal(resp)
	return data
}

// makeSuccessResponse creates a success NATSResponse.
func makeSuccessResponse(result interface{}) []byte {
	resp := NATSResponse{
		Success: true,
		Data:    result,
	}
	data, _ := json.Marshal(resp)
	return data
}
