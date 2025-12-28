package model

import (
	"sync"

	"github.com/go-playground/validator/v10"
)

var (
	validate *validator.Validate
	once     sync.Once
)

func GetValidator() *validator.Validate {
	once.Do(func() {
		validate = validator.New()
	})
	return validate
}

// FormatValidationError converts validator errors to ErrorDetail
// This is a helper for Validate() methods to keep consistent error return types
func FormatValidationError(err error) *ErrorDetail {
	if err == nil {
		return nil
	}

	// If it's a ValidationErrors type
	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		// Just take the first error for simplicity, or format all.
		// For now, let's just return the first one to match previous behavior of single error return.
		e := validationErrors[0]
		return &ErrorDetail{
			Code:    "bad_request",
			Message: "Field validation for '" + e.Field() + "' failed on the '" + e.Tag() + "' tag",
		}
	}

	return &ErrorDetail{
		Code:    "bad_request",
		Message: err.Error(),
	}
}
