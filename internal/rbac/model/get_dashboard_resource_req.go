package model

import "strings"

// GetDashboardResourceReq represents a request to get dashboard with accessible widgets
type GetDashboardResourceReq struct {
	DashboardID    string   `param:"id" validate:"required"`
	ChildWidgetIDs []string `query:"child_widget_ids"`
}

// Validate normalizes and validates the request
func (r *GetDashboardResourceReq) Validate() error {
	r.DashboardID = strings.TrimSpace(r.DashboardID)

	// TrimSpace and remove duplicates from ChildWidgetIDs
	if len(r.ChildWidgetIDs) > 0 {
		seen := make(map[string]bool)
		unique := make([]string, 0, len(r.ChildWidgetIDs))
		for _, id := range r.ChildWidgetIDs {
			trimmed := strings.TrimSpace(id)
			if trimmed != "" && !seen[trimmed] {
				seen[trimmed] = true
				unique = append(unique, trimmed)
			}
		}
		r.ChildWidgetIDs = unique
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
