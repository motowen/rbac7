package model

import "strings"

type GetUserRolesReq struct {
	UserID       string `query:"user_id"`
	Namespace    string `query:"namespace"`
	Role         string `query:"role"`
	Scope        string `query:"scope"`
	ResourceID   string `query:"resource_id"`
	ResourceType string `query:"resource_type"`
}

func (r *GetUserRolesReq) Validate() error {
	r.UserID = strings.TrimSpace(r.UserID)
	r.Namespace = strings.ToUpper(strings.TrimSpace(r.Namespace))
	r.Role = strings.ToLower(strings.TrimSpace(r.Role))
	r.Scope = strings.ToLower(strings.TrimSpace(r.Scope))
	r.ResourceID = strings.TrimSpace(r.ResourceID)
	r.ResourceType = strings.ToLower(strings.TrimSpace(r.ResourceType))

	if r.Scope == "" {
		return &ErrorDetail{Code: "bad_request", Message: "scope is required"}
	}
	if r.Scope == ScopeSystem {
		if r.Namespace == "" {
			return &ErrorDetail{Code: "bad_request", Message: "namespace required for system scope"}
		}
		if r.ResourceID != "" || r.ResourceType != "" {
			return &ErrorDetail{Code: "bad_request", Message: "invalid parameters for system scope"}
		}
	} else if r.Scope == ScopeResource {
		if r.Namespace != "" {
			return &ErrorDetail{Code: "bad_request", Message: "namespace not allowed for resource scope"}
		}
		if r.ResourceID == "" || r.ResourceType == "" {
			return &ErrorDetail{Code: "bad_request", Message: "resource_id and resource_type required for resource scope"}
		}
	}
	return nil
}
