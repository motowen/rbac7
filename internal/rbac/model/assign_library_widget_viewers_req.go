package model

import "strings"

// AssignLibraryWidgetViewersReq - Batch assign viewers to a library_widget
type AssignLibraryWidgetViewersReq struct {
	UserIDs    []string `json:"user_ids" validate:"required,min=1,max=50,dive,required"`
	ResourceID string   `json:"resource_id" validate:"required,min=1,max=50"` // Widget ID
	Namespace  string   `json:"namespace" validate:"required,min=1,max=50"`   // Publishing team
	UserType   string   `json:"user_type" validate:"omitempty,max=50"`        // Optional
}

func (r *AssignLibraryWidgetViewersReq) Validate() error {
	// Normalize inputs
	for i, id := range r.UserIDs {
		r.UserIDs[i] = strings.TrimSpace(id)
	}
	r.ResourceID = strings.TrimSpace(r.ResourceID)
	r.Namespace = strings.ToUpper(strings.TrimSpace(r.Namespace))
	r.UserType = strings.ToLower(strings.TrimSpace(r.UserType))

	// Struct validation
	if err := GetValidator().Struct(r); err != nil {
		return FormatValidationError(err)
	}

	if len(r.UserIDs) == 0 {
		return &ErrorDetail{Code: "bad_request", Message: "user_ids cannot be empty"}
	}

	return nil
}
