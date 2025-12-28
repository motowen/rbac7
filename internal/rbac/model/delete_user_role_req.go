package model

type DeleteSystemUserRoleReq struct {
	Namespace string `query:"namespace"`
	UserID    string `query:"user_id"`
}

func (r *DeleteSystemUserRoleReq) Validate() error {
	if r.Namespace == "" {
		return &ErrorDetail{Code: "bad_request", Message: "namespace is required"}
	}
	if r.UserID == "" {
		return &ErrorDetail{Code: "bad_request", Message: "user_id is required"}
	}
	return nil
}

type DeleteResourceUserRoleReq struct {
	UserID       string `query:"user_id"`
	ResourceID   string `query:"resource_id"`
	ResourceType string `query:"resource_type"`
}

func (r *DeleteResourceUserRoleReq) Validate() error {
	if r.UserID == "" {
		return &ErrorDetail{Code: "bad_request", Message: "user_id is required"}
	}
	if r.ResourceID == "" {
		return &ErrorDetail{Code: "bad_request", Message: "resource_id is required"}
	}
	if r.ResourceType == "" {
		return &ErrorDetail{Code: "bad_request", Message: "resource_type is required"}
	}
	return nil
}
