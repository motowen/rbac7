package model

import "strings"

type AssignResourceOwnerReq struct {
	ResourceID   string `json:"resource_id" validate:"required,min=1,max=50"`
	ResourceType string `json:"resource_type" validate:"required,min=1,max=50"`
}

func (r *AssignResourceOwnerReq) Validate() error {
	r.ResourceID = strings.TrimSpace(r.ResourceID)
	r.ResourceType = strings.ToLower(strings.TrimSpace(r.ResourceType))

	if err := GetValidator().Struct(r); err != nil {
		return FormatValidationError(err)
	}
	return nil
}
