package model

import "strings"

type GetUserRolesReq struct {
	UserID       string `query:"user_id" validate:"omitempty,max=50"`
	Namespace    string `query:"namespace" validate:"omitempty,max=50"`
	Role         string `query:"role" validate:"omitempty,max=50"`
	Scope        string `query:"scope" validate:"required,min=1,max=50"`
	ResourceID   string `query:"resource_id" validate:"omitempty,max=50"`
	ResourceType string `query:"resource_type" validate:"omitempty,max=50"`
}

func (r *GetUserRolesReq) Validate() error {
	r.UserID = strings.TrimSpace(r.UserID)
	r.Namespace = strings.ToUpper(strings.TrimSpace(r.Namespace))
	r.Role = strings.ToLower(strings.TrimSpace(r.Role))
	r.Scope = strings.ToLower(strings.TrimSpace(r.Scope))
	r.ResourceID = strings.TrimSpace(r.ResourceID)
	r.ResourceType = strings.ToLower(strings.TrimSpace(r.ResourceType))

	if err := GetValidator().Struct(r); err != nil {
		return FormatValidationError(err)
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
