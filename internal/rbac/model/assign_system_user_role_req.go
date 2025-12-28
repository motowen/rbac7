package model

import "strings"

type AssignSystemUserRoleReq struct {
	UserID    string `json:"user_id"`
	Role      string `json:"role"`
	Namespace string `json:"namespace"`
	UserType  string `json:"user_type"` // Optional, defaults to member
}

func (r *AssignSystemUserRoleReq) Validate() error {
	r.UserID = strings.TrimSpace(r.UserID)
	r.Role = strings.ToLower(strings.TrimSpace(r.Role))
	r.Namespace = strings.ToUpper(strings.TrimSpace(r.Namespace))
	r.UserType = strings.ToLower(strings.TrimSpace(r.UserType))

	if r.UserID == "" {
		return &ErrorDetail{Code: "bad_request", Message: "user_id is required"}
	}
	if r.Role == "" {
		return &ErrorDetail{Code: "bad_request", Message: "role is required"}
	}
	if r.Namespace == "" {
		return &ErrorDetail{Code: "bad_request", Message: "namespace is required"}
	}
	return nil
}
