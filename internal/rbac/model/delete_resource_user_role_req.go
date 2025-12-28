package model

import "strings"

type DeleteResourceUserRoleReq struct {
	UserID       string `query:"user_id"`
	ResourceID   string `query:"resource_id"`
	ResourceType string `query:"resource_type"`
}

func (r *DeleteResourceUserRoleReq) Validate() error {
	r.UserID = strings.TrimSpace(r.UserID)
	r.ResourceID = strings.TrimSpace(r.ResourceID)
	r.ResourceType = strings.ToLower(strings.TrimSpace(r.ResourceType))

	if r.UserID == "" {
		return &ErrorDetail{Code: "bad_request", Message: "user_id is required"}
	}
	if r.ResourceID == "" {
		return &ErrorDetail{Code: "bad_request", Message: "resource_id is required"}
	}
	if r.ResourceType == "" {
		return &ErrorDetail{Code: "bad_request", Message: "resource_type is required"}
	}
	return nil
}
