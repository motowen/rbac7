package model

import "strings"

type TransferResourceOwnerReq struct {
	UserID       string `json:"user_id"`
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
}

func (r *TransferResourceOwnerReq) Validate() error {
	r.UserID = strings.TrimSpace(r.UserID)
	r.ResourceID = strings.TrimSpace(r.ResourceID)
	r.ResourceType = strings.ToLower(strings.TrimSpace(r.ResourceType))

	if r.UserID == "" {
		return &ErrorDetail{Code: "bad_request", Message: "user_id is required"}
	}
	if r.ResourceID == "" || r.ResourceType == "" {
		return &ErrorDetail{Code: "bad_request", Message: "resource params required"}
	}
	return nil
}
