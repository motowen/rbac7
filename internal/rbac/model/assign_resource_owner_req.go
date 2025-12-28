package model

import "strings"

type AssignResourceOwnerReq struct {
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
	// UserID ignored by service (uses caller)
}

func (r *AssignResourceOwnerReq) Validate() error {
	r.ResourceID = strings.TrimSpace(r.ResourceID)
	r.ResourceType = strings.ToLower(strings.TrimSpace(r.ResourceType))

	if r.ResourceID == "" || r.ResourceType == "" {
		return &ErrorDetail{Code: "bad_request", Message: "resource params required"}
	}
	return nil
}
