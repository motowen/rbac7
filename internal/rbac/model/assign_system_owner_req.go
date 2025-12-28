package model

import "strings"

type AssignSystemOwnerReq struct {
	UserID    string `json:"user_id" validate:"required,min=1,max=50"`
	Namespace string `json:"namespace" validate:"required,min=1,max=50"`
}

func (r *AssignSystemOwnerReq) Validate() error {
	r.UserID = strings.TrimSpace(r.UserID)
	r.Namespace = strings.ToUpper(strings.TrimSpace(r.Namespace))

	if err := GetValidator().Struct(r); err != nil {
		return FormatValidationError(err)
	}
	return nil
}
