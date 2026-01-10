package model

import "strings"

// AllowedResourceRoles defines which roles can be assigned for resource scope
var AllowedResourceRoles = map[string]bool{
	RoleResourceAdmin:  true,
	RoleResourceEditor: true,
	RoleResourceViewer: true,
}

type AssignResourceUserRolesReq struct {
	UserIDs          []string `json:"user_ids" validate:"required,min=1,max=50,dive,required"`
	Role             string   `json:"role" validate:"required,min=1,max=50"`
	ResourceID       string   `json:"resource_id" validate:"required,min=1,max=50"`
	ResourceType     string   `json:"resource_type" validate:"required,min=1,max=50"`
	ParentResourceID string   `json:"parent_resource_id" validate:"omitempty,max=50"`
	UserType         string   `json:"user_type" validate:"omitempty,max=50"` // Optional
}

func (r *AssignResourceUserRolesReq) Validate() error {
	for i, id := range r.UserIDs {
		r.UserIDs[i] = strings.TrimSpace(id)
	}
	r.Role = strings.ToLower(strings.TrimSpace(r.Role))
	r.ResourceID = strings.TrimSpace(r.ResourceID)
	r.ResourceType = strings.ToLower(strings.TrimSpace(r.ResourceType))
	r.ParentResourceID = strings.TrimSpace(r.ParentResourceID)
	r.UserType = strings.ToLower(strings.TrimSpace(r.UserType))

	// 1. Basic Struct Validation (required, min/max)
	if err := GetValidator().Struct(r); err != nil {
		return FormatValidationError(err)
	}

	// 2. Business Logic Validation
	if len(r.UserIDs) == 0 {
		return &ErrorDetail{Code: "bad_request", Message: "user_ids cannot be empty"}
	}

	if r.Role == RoleResourceOwner {
		return &ErrorDetail{Code: "bad_request", Message: "cannot assign resource owner role via this API"}
	}

	// Allowed roles check
	if !AllowedResourceRoles[r.Role] {
		return &ErrorDetail{Code: "bad_request", Message: "invalid role: must be one of [admin, editor, viewer]"}
	}

	if r.ResourceType == ResourceTypeDashboardWidget && r.ParentResourceID == "" {
		return &ErrorDetail{Code: "bad_request", Message: "parent_resource_id is required for dashboard_widget"}
	}

	return nil
}
