package model

import "strings"

type TransferSystemOwnerReq struct {
	UserID    string `json:"user_id"`
	Namespace string `json:"namespace"`
}

func (r *TransferSystemOwnerReq) Validate() error {
	r.UserID = strings.TrimSpace(r.UserID)
	r.Namespace = strings.ToUpper(strings.TrimSpace(r.Namespace))

	if r.UserID == "" {
		return &ErrorDetail{Code: "bad_request", Message: "user_id is required"}
	}
	if r.Namespace == "" {
		return &ErrorDetail{Code: "bad_request", Message: "namespace is required"}
	}
	return nil
}
