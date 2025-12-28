package model

import "strings"

type AssignResourceUserRoleReq struct {
	UserID       string `json:"user_id"`
	Role         string `json:"role"`
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
	UserType     string `json:"user_type"` // Optional
}

func (r *AssignResourceUserRoleReq) Validate() error {
	r.UserID = strings.TrimSpace(r.UserID)
	r.Role = strings.ToLower(strings.TrimSpace(r.Role))
	r.ResourceID = strings.TrimSpace(r.ResourceID)
	r.ResourceType = strings.ToLower(strings.TrimSpace(r.ResourceType))
	r.UserType = strings.ToLower(strings.TrimSpace(r.UserType))

	if r.UserID == "" {
		return &ErrorDetail{Code: "bad_request", Message: "user_id is required"}
	}
	if r.Role == "" {
		return &ErrorDetail{Code: "bad_request", Message: "role is required"}
	}
	if r.ResourceID == "" {
		return &ErrorDetail{Code: "bad_request", Message: "resource_id is required"}
	}
	if r.ResourceType == "" {
		return &ErrorDetail{Code: "bad_request", Message: "resource_type is required"}
	}
	return nil
}
