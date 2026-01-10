package model

import "strings"

type DeleteResourceUserRoleReq struct {
	UserID           string `query:"user_id" validate:"required,min=1,max=50"`
	ResourceID       string `query:"resource_id" validate:"required,min=1,max=50"`
	ResourceType     string `query:"resource_type" validate:"required,min=1,max=50"`
	ParentResourceID string `query:"parent_resource_id" validate:"omitempty,max=50"`
}

func (r *DeleteResourceUserRoleReq) Validate() error {
	r.UserID = strings.TrimSpace(r.UserID)
	r.ResourceID = strings.TrimSpace(r.ResourceID)
	r.ResourceType = strings.ToLower(strings.TrimSpace(r.ResourceType))
	r.ParentResourceID = strings.TrimSpace(r.ParentResourceID)

	if err := GetValidator().Struct(r); err != nil {
		return FormatValidationError(err)
	}

	if r.ResourceType == ResourceTypeDashboardWidget && r.ParentResourceID == "" {
		return &ErrorDetail{Code: "bad_request", Message: "parent_resource_id is required for dashboard_widget"}
	}
	return nil
}
