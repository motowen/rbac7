package model

import "strings"

type DeleteResourceUserRoleReq struct {
	UserID       string `query:"user_id" validate:"required,min=1,max=50"`
	ResourceID   string `query:"resource_id" validate:"required,min=1,max=50"`
	ResourceType string `query:"resource_type" validate:"required,min=1,max=50"`
}

func (r *DeleteResourceUserRoleReq) Validate() error {
	r.UserID = strings.TrimSpace(r.UserID)
	r.ResourceID = strings.TrimSpace(r.ResourceID)
	r.ResourceType = strings.ToLower(strings.TrimSpace(r.ResourceType))

	if err := GetValidator().Struct(r); err != nil {
		return FormatValidationError(err)
	}
	return nil
}
