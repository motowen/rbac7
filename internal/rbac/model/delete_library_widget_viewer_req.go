package model

import "strings"

// DeleteLibraryWidgetViewerReq - Remove a viewer from a library_widget
type DeleteLibraryWidgetViewerReq struct {
	UserID     string `json:"user_id" validate:"required,min=1,max=50"`
	ResourceID string `json:"resource_id" validate:"required,min=1,max=50"`
	Namespace  string `json:"namespace" validate:"required,min=1,max=50"`
}

func (r *DeleteLibraryWidgetViewerReq) Validate() error {
	r.UserID = strings.TrimSpace(r.UserID)
	r.ResourceID = strings.TrimSpace(r.ResourceID)
	r.Namespace = strings.ToUpper(strings.TrimSpace(r.Namespace))

	if err := GetValidator().Struct(r); err != nil {
		return FormatValidationError(err)
	}

	return nil
}
