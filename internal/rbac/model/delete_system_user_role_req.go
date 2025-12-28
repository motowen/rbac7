package model

import "strings"

type DeleteSystemUserRoleReq struct {
	Namespace string `query:"namespace"`
	UserID    string `query:"user_id"`
}

func (r *DeleteSystemUserRoleReq) Validate() error {
	r.Namespace = strings.ToUpper(strings.TrimSpace(r.Namespace))
	r.UserID = strings.TrimSpace(r.UserID)

	if r.Namespace == "" {
		return &ErrorDetail{Code: "bad_request", Message: "namespace is required"}
	}
	if r.UserID == "" {
		return &ErrorDetail{Code: "bad_request", Message: "user_id is required"}
	}
	return nil
}
