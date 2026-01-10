package model

import "strings"

type CheckPermissionReq struct {
	Permission       string `json:"permission" validate:"required,min=1,max=100"`
	Scope            string `json:"scope" validate:"required,min=1,max=50"`
	Namespace        string `json:"namespace" validate:"omitempty,max=50"`
	ResourceID       string `json:"resource_id" validate:"omitempty,max=50"`
	ResourceType     string `json:"resource_type" validate:"omitempty,max=50"`
	ParentResourceID string `json:"parent_resource_id" validate:"omitempty,max=50"`
}

func (r *CheckPermissionReq) Validate() error {
	r.Permission = strings.TrimSpace(r.Permission)
	r.Scope = strings.ToLower(strings.TrimSpace(r.Scope))
	r.Namespace = strings.ToUpper(strings.TrimSpace(r.Namespace))
	r.ResourceID = strings.TrimSpace(r.ResourceID)
	r.ResourceType = strings.ToLower(strings.TrimSpace(r.ResourceType))
	r.ParentResourceID = strings.TrimSpace(r.ParentResourceID)

	if err := GetValidator().Struct(r); err != nil {
		return FormatValidationError(err)
	}

	if r.Scope == ScopeResource {
		if r.ResourceID == "" || r.ResourceType == "" {
			return &ErrorDetail{Code: "bad_request", Message: "resource params required for resource scope"}
		}
		if r.ResourceType == ResourceTypeDashboardWidget && r.ParentResourceID == "" {
			return &ErrorDetail{Code: "bad_request", Message: "parent_resource_id is required for dashboard_widget"}
		}
	}
	return nil
}
