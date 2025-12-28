package model

type GetUserRolesMeReq struct {
	Scope        string `query:"scope"`
	ResourceType string `query:"resource_type"`
}

func (r *GetUserRolesMeReq) Validate() error {
	if r.Scope == "" {
		return &ErrorDetail{Code: "bad_request", Message: "scope is required"}
	}
	if r.Scope != ScopeSystem && r.Scope != ScopeResource {
		return &ErrorDetail{Code: "bad_request", Message: "invalid scope"}
	}
	if r.Scope == ScopeResource && r.ResourceType == "" {
		return &ErrorDetail{Code: "bad_request", Message: "resource_type is required for resource scope"}
	}
	if r.Scope == ScopeSystem && r.ResourceType != "" {
		return &ErrorDetail{Code: "bad_request", Message: "resource_type should be empty for system scope"}
	}
	return nil
}
