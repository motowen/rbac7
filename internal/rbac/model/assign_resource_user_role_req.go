package model

import "strings"

type AssignResourceUserRoleReq struct {
	UserID           string `json:"user_id" validate:"required,min=1,max=50"`
	Role             string `json:"role" validate:"required,min=1,max=50"`
	ResourceID       string `json:"resource_id" validate:"required,min=1,max=50"`
	ResourceType     string `json:"resource_type" validate:"required,min=1,max=50"`
	ParentResourceID string `json:"parent_resource_id" validate:"omitempty,max=50"`
	UserType         string `json:"user_type" validate:"omitempty,max=50"` // Optional
}

func (r *AssignResourceUserRoleReq) Validate() error {
	r.UserID = strings.TrimSpace(r.UserID)
	r.Role = strings.ToLower(strings.TrimSpace(r.Role))
	r.ResourceID = strings.TrimSpace(r.ResourceID)
	r.ResourceType = strings.ToLower(strings.TrimSpace(r.ResourceType))
	r.ParentResourceID = strings.TrimSpace(r.ParentResourceID)
	r.UserType = strings.ToLower(strings.TrimSpace(r.UserType))

	if err := GetValidator().Struct(r); err != nil {
		return FormatValidationError(err)
	}

	if r.ResourceType == ResourceTypeWidget && r.ParentResourceID == "" {
		return &ErrorDetail{Code: "bad_request", Message: "parent_resource_id is required for dashboard_widget"}
	}
	return nil
}
