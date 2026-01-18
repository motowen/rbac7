package model

import "strings"

type DeleteSystemUserRoleReq struct {
	Namespace string `query:"namespace" validate:"required,min=1,max=50"`
	UserID    string `query:"user_id" validate:"required,min=1,max=50"`
	UserType  string `query:"user_type" validate:"omitempty,max=50"` // Optional
}

func (r *DeleteSystemUserRoleReq) Validate() error {
	r.Namespace = strings.ToUpper(strings.TrimSpace(r.Namespace))
	r.UserID = strings.TrimSpace(r.UserID)
	r.UserType = strings.ToLower(strings.TrimSpace(r.UserType))

	if err := GetValidator().Struct(r); err != nil {
		return FormatValidationError(err)
	}
	return nil
}
