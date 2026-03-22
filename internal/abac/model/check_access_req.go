package model

import "fmt"

// --- Check Access Requests ---

// CheckAccessReq is the request for a single access check
type CheckAccessReq struct {
	SubjectID string        `json:"subject_id"`
	Resource  ResourceAttrs `json:"resource"`
	Action    string        `json:"action"`
}

// Validate validates the CheckAccessReq
func (r *CheckAccessReq) Validate() error {
	if r.SubjectID == "" {
		return fmt.Errorf("subject_id is required")
	}
	if r.Action == "" {
		return fmt.Errorf("action is required")
	}
	if r.Resource.ResourceID == "" {
		return fmt.Errorf("resource.resource_id is required")
	}
	if r.Resource.ResourceType == "" {
		return fmt.Errorf("resource.resource_type is required")
	}
	return nil
}

// BatchCheckAccessReq is the request for batch access checks
type BatchCheckAccessReq struct {
	SubjectID string          `json:"subject_id"`
	Resources []ResourceAttrs `json:"resources"`
	Action    string          `json:"action"`
}

// Validate validates the BatchCheckAccessReq
func (r *BatchCheckAccessReq) Validate() error {
	if r.SubjectID == "" {
		return fmt.Errorf("subject_id is required")
	}
	if r.Action == "" {
		return fmt.Errorf("action is required")
	}
	if len(r.Resources) == 0 {
		return fmt.Errorf("resources is required and must not be empty")
	}
	for i, res := range r.Resources {
		if res.ResourceID == "" {
			return fmt.Errorf("resources[%d].resource_id is required", i)
		}
		if res.ResourceType == "" {
			return fmt.Errorf("resources[%d].resource_type is required", i)
		}
	}
	return nil
}
