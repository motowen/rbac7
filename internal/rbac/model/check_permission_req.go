package model

import "strings"

type CheckPermissionReq struct {
	Permission   string `json:"permission"`
	Scope        string `json:"scope"`
	Namespace    string `json:"namespace"`
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
}

func (r *CheckPermissionReq) Validate() error {
	r.Permission = strings.TrimSpace(r.Permission)
	r.Scope = strings.ToLower(strings.TrimSpace(r.Scope))
	r.Namespace = strings.ToUpper(strings.TrimSpace(r.Namespace))
	r.ResourceID = strings.TrimSpace(r.ResourceID)
	r.ResourceType = strings.ToLower(strings.TrimSpace(r.ResourceType))

	if r.Permission == "" {
		return &ErrorDetail{Code: "bad_request", Message: "permission is required"}
	}
	if r.Scope == "" {
		return &ErrorDetail{Code: "bad_request", Message: "scope is required"}
	}
	if r.Scope == ScopeResource && (r.ResourceID == "" || r.ResourceType == "") {
		return &ErrorDetail{Code: "bad_request", Message: "resource params required for resource scope"}
	}
	return nil
}
