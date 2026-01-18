package model

import (
	"strings"
	"time"
)

// GetUserRoleHistoryReq 統一查詢 (支援 system 和 resource scope)
type GetUserRoleHistoryReq struct {
	// Scope (required)
	Scope string `query:"scope" validate:"required,oneof=system resource"`

	// System Scope 參數
	Namespace string `query:"namespace" validate:"omitempty,max=50"`

	// Resource Scope 參數
	ResourceID       string   `query:"resource_id" validate:"omitempty,max=50"`
	ResourceType     string   `query:"resource_type" validate:"omitempty,max=50"` // dashboard
	ChildResourceIDs []string `query:"child_resource_ids"`                        // 查詢 dashboard_widgets

	// Time Filter
	StartTime *time.Time `query:"start_time"`
	EndTime   *time.Time `query:"end_time"`

	// Pagination
	Page int `query:"page" validate:"omitempty,min=1"`
	Size int `query:"size" validate:"omitempty,min=1,max=1000"`
}

func (r *GetUserRoleHistoryReq) Validate() error {
	r.Scope = strings.ToLower(strings.TrimSpace(r.Scope))
	r.Namespace = strings.ToUpper(strings.TrimSpace(r.Namespace))
	r.ResourceID = strings.TrimSpace(r.ResourceID)
	r.ResourceType = strings.ToLower(strings.TrimSpace(r.ResourceType))

	// Trim child resource IDs
	for i, id := range r.ChildResourceIDs {
		r.ChildResourceIDs[i] = strings.TrimSpace(id)
	}

	// Set default pagination
	if r.Page <= 0 {
		r.Page = 1
	}
	if r.Size <= 0 {
		r.Size = 100 // Default size
	}
	if r.Size > 1000 {
		r.Size = 1000 // Max size
	}

	if err := GetValidator().Struct(r); err != nil {
		return FormatValidationError(err)
	}

	// Business logic validation
	if r.Scope == ScopeSystem && r.Namespace == "" {
		return &ErrorDetail{Code: "bad_request", Message: "namespace is required for system scope"}
	}

	if r.Scope == ScopeResource {
		if r.ResourceID == "" {
			return &ErrorDetail{Code: "bad_request", Message: "resource_id is required for resource scope"}
		}
		if r.ResourceType == "" {
			return &ErrorDetail{Code: "bad_request", Message: "resource_type is required for resource scope"}
		}
	}

	return nil
}

// GetUserRoleHistoryResp 分頁回應
type GetUserRoleHistoryResp struct {
	Data       []*UserRoleHistory `json:"data"`
	Page       int                `json:"page"`
	Size       int                `json:"size"`
	TotalCount int64              `json:"total_count"`
}
