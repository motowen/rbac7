package model

import "strings"

type AssignSystemUserRoleReq struct {
	UserID    string `json:"user_id" validate:"required,min=1,max=50"`
	Role      string `json:"role" validate:"required,min=1,max=50"`
	Namespace string `json:"namespace" validate:"required,min=1,max=50"`
	UserType  string `json:"user_type" validate:"omitempty,max=50"` // Optional, defaults to member
}

func (r *AssignSystemUserRoleReq) Validate() error {
	r.UserID = strings.TrimSpace(r.UserID)
	r.Role = strings.ToLower(strings.TrimSpace(r.Role))
	r.Namespace = strings.ToUpper(strings.TrimSpace(r.Namespace))
	r.UserType = strings.ToLower(strings.TrimSpace(r.UserType))

	if err := GetValidator().Struct(r); err != nil {
		return FormatValidationError(err)
	}

	// Business Logic Validation
	if r.Role == RoleSystemOwner {
		return &ErrorDetail{Code: "bad_request", Message: "cannot assign system owner role via this API"}
	}

	// Allowed roles check
	if !AllowedSystemRoles[r.Role] {
		return &ErrorDetail{Code: "bad_request", Message: "invalid role: must be one of [admin, viewer, dev_user]"}
	}

	return nil
}
