package model

import "strings"

type BatchCheckPermissionReq struct {
	Permission   string   `json:"permission" validate:"required,min=1,max=100"`
	ResourceType string   `json:"resource_type" validate:"required,min=1,max=50"`
	ResourceIDs  []string `json:"resource_ids" validate:"required,min=1,max=100"`
}

type BatchCheckPermissionResponse struct {
	Results map[string]bool `json:"results"`
}

func (r *BatchCheckPermissionReq) Validate() error {
	r.Permission = strings.TrimSpace(r.Permission)
	r.ResourceType = strings.ToLower(strings.TrimSpace(r.ResourceType))

	if err := GetValidator().Struct(r); err != nil {
		return FormatValidationError(err)
	}

	// Validate individual resource IDs
	seen := make(map[string]bool, len(r.ResourceIDs))
	for i, id := range r.ResourceIDs {
		r.ResourceIDs[i] = strings.TrimSpace(id)
		if r.ResourceIDs[i] == "" {
			return &ErrorDetail{Code: "bad_request", Message: "resource_ids contains empty value"}
		}
		if seen[r.ResourceIDs[i]] {
			return &ErrorDetail{Code: "bad_request", Message: "resource_ids contains duplicate value: " + r.ResourceIDs[i]}
		}
		seen[r.ResourceIDs[i]] = true
	}

	return nil
}
