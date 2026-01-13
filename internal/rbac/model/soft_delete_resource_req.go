package model

import "strings"

// SoftDeleteResourceReq represents a request to soft delete all user roles for a resource
type SoftDeleteResourceReq struct {
	ResourceID       string   `json:"resource_id" validate:"required"`
	ResourceType     string   `json:"resource_type" validate:"required,oneof=dashboard dashboard_widget library_widget"`
	ParentResourceID string   `json:"parent_resource_id,omitempty"` // Required for dashboard_widget
	ChildResourceIDs []string `json:"child_resource_ids,omitempty"` // For dashboard: also delete widget roles
	Namespace        string   `json:"namespace,omitempty"`          // Required for library_widget
}

func (r *SoftDeleteResourceReq) Validate() error {
	r.ResourceID = strings.TrimSpace(r.ResourceID)
	r.ResourceType = strings.ToLower(strings.TrimSpace(r.ResourceType))
	r.ParentResourceID = strings.TrimSpace(r.ParentResourceID)

	// Namespace: TrimSpace and uppercase
	if r.Namespace != "" {
		r.Namespace = strings.ToUpper(strings.TrimSpace(r.Namespace))
	}

	// ChildResourceIDs: TrimSpace and remove duplicates
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
