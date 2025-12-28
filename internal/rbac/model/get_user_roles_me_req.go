package model

import "strings"

type GetUserRolesMeReq struct {
	Scope        string `query:"scope" validate:"required,min=1,max=50"`
	ResourceType string `query:"resource_type" validate:"omitempty,max=50"`
}

func (r *GetUserRolesMeReq) Validate() error {
	r.Scope = strings.ToLower(strings.TrimSpace(r.Scope))
	r.ResourceType = strings.ToLower(strings.TrimSpace(r.ResourceType))

	if err := GetValidator().Struct(r); err != nil {
		return FormatValidationError(err)
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
