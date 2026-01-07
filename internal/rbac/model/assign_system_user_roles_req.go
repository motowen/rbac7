package model

import "strings"

type AssignSystemUserRolesReq struct {
	UserIDs   []string `json:"user_ids" validate:"required,min=1,max=50,dive,required"`
	Role      string   `json:"role" validate:"required,min=1,max=50"`
	Namespace string   `json:"namespace" validate:"required,min=1,max=50"`
	UserType  string   `json:"user_type" validate:"omitempty,max=50"` // Optional, defaults to member
}

func (r *AssignSystemUserRolesReq) Validate() error {
	for i, id := range r.UserIDs {
		r.UserIDs[i] = strings.TrimSpace(id)
	}
	r.Role = strings.ToLower(strings.TrimSpace(r.Role))
	r.Namespace = strings.ToUpper(strings.TrimSpace(r.Namespace))
	r.UserType = strings.ToLower(strings.TrimSpace(r.UserType))

	// 1. Basic Struct Validation (required, min/max)
	if err := GetValidator().Struct(r); err != nil {
		return FormatValidationError(err)
	}

	// 2. Business Logic Validation
	if len(r.UserIDs) == 0 {
		return &ErrorDetail{Code: "bad_request", Message: "user_ids cannot be empty"}
	}

	if r.Role == RoleSystemOwner {
		return &ErrorDetail{Code: "bad_request", Message: "cannot assign system owner role via this API"}
	}

	// Allowed roles check
	if !AllowedSystemRoles[r.Role] {
		return &ErrorDetail{Code: "bad_request", Message: "invalid role: must be one of [admin, viewer, dev_user]"}
	}

	return nil
}
