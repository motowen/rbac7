package model

import "strings"

// GetDashboardResourceReq represents a request to get dashboard with accessible widgets
type GetDashboardResourceReq struct {
	ResourceID       string   `json:"resource_id" validate:"required,min=1,max=50"`
	ResourceType     string   `json:"resource_type" validate:"required,min=1,max=50"`
	ChildResourceIDs []string `json:"child_resource_ids"`
}

// Validate normalizes and validates the request
func (r *GetDashboardResourceReq) Validate() error {
	r.ResourceID = strings.TrimSpace(r.ResourceID)
	r.ResourceType = strings.TrimSpace(r.ResourceType)

	// TrimSpace and remove duplicates from ChildResourceIDs
	if len(r.ChildResourceIDs) > 0 {
		seen := make(map[string]bool)
		unique := make([]string, 0, len(r.ChildResourceIDs))
		for _, id := range r.ChildResourceIDs {
			trimmed := strings.TrimSpace(id)
			if trimmed != "" && !seen[trimmed] {
				seen[trimmed] = true
				unique = append(unique, trimmed)
			}
		}
		r.ChildResourceIDs = unique
	}

	if err := GetValidator().Struct(r); err != nil {
		return FormatValidationError(err)
	}

	return nil
}

// GetDashboardResourceResp represents the response for get dashboard resource
type GetDashboardResourceResp struct {
	UserRoles           []*UserRoleDTO `json:"user_roles"`
	AccessibleWidgetIDs []string       `json:"accessible_widget_ids"`
}

// UserRoleDTO is a simplified user role for API response
type UserRoleDTO struct {
	UserID   string `json:"user_id"`
	UserType string `json:"user_type,omitempty"`
	Role     string `json:"role"`
}
