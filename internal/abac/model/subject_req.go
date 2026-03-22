package model

import "fmt"

// --- Subject CRUD Requests ---

// CreateSubjectReq is the request to create a new subject
type CreateSubjectReq struct {
	UserID           string          `json:"user_id"`
	Role             string          `json:"role"`
	Status           string          `json:"status"`
	SensitivityLevel string          `json:"sensitivity_level,omitempty"`
	Orgs             []OrgMembership `json:"orgs,omitempty"`
	GroupIDs         []string        `json:"group_ids,omitempty"`
	CustomAttrs      []CustomAttr    `json:"custom_attrs,omitempty"`
}

// Validate validates the CreateSubjectReq
func (r *CreateSubjectReq) Validate() error {
	if r.UserID == "" {
		return fmt.Errorf("user_id is required")
	}
	if r.Role == "" {
		return fmt.Errorf("role is required")
	}
	if r.Status == "" {
		return fmt.Errorf("status is required")
	}
	return nil
}

// UpdateSubjectReq is the request to update an existing subject
type UpdateSubjectReq struct {
	UserID           string          `json:"user_id"`
	Role             *string         `json:"role,omitempty"`
	Status           *string         `json:"status,omitempty"`
	SensitivityLevel *string         `json:"sensitivity_level,omitempty"`
	Orgs             []OrgMembership `json:"orgs,omitempty"`
	GroupIDs         []string        `json:"group_ids,omitempty"`
	CustomAttrs      []CustomAttr    `json:"custom_attrs,omitempty"`
}

// Validate validates the UpdateSubjectReq
func (r *UpdateSubjectReq) Validate() error {
	if r.UserID == "" {
		return fmt.Errorf("user_id is required")
	}
	return nil
}

// --- Group Operations ---

// AddSubjectToGroupReq is the request to add a subject to a group
type AddSubjectToGroupReq struct {
	UserID  string `json:"user_id"`
	GroupID string `json:"group_id"`
}

// Validate validates the AddSubjectToGroupReq
func (r *AddSubjectToGroupReq) Validate() error {
	if r.UserID == "" {
		return fmt.Errorf("user_id is required")
	}
	if r.GroupID == "" {
		return fmt.Errorf("group_id is required")
	}
	return nil
}

// RemoveSubjectFromGroupReq is the request to remove a subject from a group
type RemoveSubjectFromGroupReq struct {
	UserID  string `json:"user_id"`
	GroupID string `json:"group_id"`
}

// Validate validates the RemoveSubjectFromGroupReq
func (r *RemoveSubjectFromGroupReq) Validate() error {
	if r.UserID == "" {
		return fmt.Errorf("user_id is required")
	}
	if r.GroupID == "" {
		return fmt.Errorf("group_id is required")
	}
	return nil
}

// --- Org Operations ---

// UpsertOrgMembershipReq is the request to upsert an org membership
type UpsertOrgMembershipReq struct {
	UserID  string        `json:"user_id"`
	Org     OrgMembership `json:"org"`
}

// Validate validates the UpsertOrgMembershipReq
func (r *UpsertOrgMembershipReq) Validate() error {
	if r.UserID == "" {
		return fmt.Errorf("user_id is required")
	}
	if r.Org.OrgID == "" {
		return fmt.Errorf("org.org_id is required")
	}
	if r.Org.OrgType == "" {
		return fmt.Errorf("org.org_type is required")
	}
	return nil
}

// RemoveOrgMembershipReq is the request to remove an org membership
type RemoveOrgMembershipReq struct {
	UserID string `json:"user_id"`
	OrgID  string `json:"org_id"`
}

// Validate validates the RemoveOrgMembershipReq
func (r *RemoveOrgMembershipReq) Validate() error {
	if r.UserID == "" {
		return fmt.Errorf("user_id is required")
	}
	if r.OrgID == "" {
		return fmt.Errorf("org_id is required")
	}
	return nil
}

// --- Policy Rule Requests ---

// CreatePolicyRuleReq is the request to create a policy rule
type CreatePolicyRuleReq struct {
	Name         string       `json:"name"`
	Description  string       `json:"description,omitempty"`
	ResourceType string       `json:"resource_type"`
	Action       string       `json:"action"`
	Effect       string       `json:"effect"`
	Priority     int          `json:"priority"`
	Conditions   ConditionSet `json:"conditions"`
	Enabled      bool         `json:"enabled"`
}

// Validate validates the CreatePolicyRuleReq
func (r *CreatePolicyRuleReq) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("name is required")
	}
	if r.ResourceType == "" {
		return fmt.Errorf("resource_type is required")
	}
	if r.Action == "" {
		return fmt.Errorf("action is required")
	}
	if r.Effect != EffectAllow && r.Effect != EffectDeny {
		return fmt.Errorf("effect must be 'allow' or 'deny'")
	}
	// Validate conditions operators
	for _, cond := range r.Conditions.Subject {
		if !ValidOperators[cond.Operator] {
			return fmt.Errorf("invalid operator: %s", cond.Operator)
		}
	}
	for _, cond := range r.Conditions.Resource {
		if !ValidOperators[cond.Operator] {
			return fmt.Errorf("invalid operator: %s", cond.Operator)
		}
	}
	return nil
}

// UpdatePolicyRuleReq is the request to update a policy rule
type UpdatePolicyRuleReq struct {
	ID           string        `json:"id"`
	Name         *string       `json:"name,omitempty"`
	Description  *string       `json:"description,omitempty"`
	ResourceType *string       `json:"resource_type,omitempty"`
	Action       *string       `json:"action,omitempty"`
	Effect       *string       `json:"effect,omitempty"`
	Priority     *int          `json:"priority,omitempty"`
	Conditions   *ConditionSet `json:"conditions,omitempty"`
	Enabled      *bool         `json:"enabled,omitempty"`
}

// Validate validates the UpdatePolicyRuleReq
func (r *UpdatePolicyRuleReq) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("id is required")
	}
	if r.Effect != nil && *r.Effect != EffectAllow && *r.Effect != EffectDeny {
		return fmt.Errorf("effect must be 'allow' or 'deny'")
	}
	if r.Conditions != nil {
		for _, cond := range r.Conditions.Subject {
			if !ValidOperators[cond.Operator] {
				return fmt.Errorf("invalid operator: %s", cond.Operator)
			}
		}
		for _, cond := range r.Conditions.Resource {
			if !ValidOperators[cond.Operator] {
				return fmt.Errorf("invalid operator: %s", cond.Operator)
			}
		}
	}
	return nil
}

// --- Attribute Definition Requests ---

// CreateAttributeDefinitionReq is the request to create an attribute definition
type CreateAttributeDefinitionReq struct {
	Key           string   `json:"key"`
	Scope         string   `json:"scope"`
	ResourceType  string   `json:"resource_type,omitempty"`
	Type          string   `json:"type"`
	ManagedBy     string   `json:"managed_by"`
	Operators     []string `json:"operators"`
	AllowedValues []string `json:"allowed_values,omitempty"`
}

// Validate validates the CreateAttributeDefinitionReq
func (r *CreateAttributeDefinitionReq) Validate() error {
	if r.Key == "" {
		return fmt.Errorf("key is required")
	}
	if r.Scope != ScopeSubject && r.Scope != ScopeResource {
		return fmt.Errorf("scope must be 'subject' or 'resource'")
	}
	if r.Type != AttrTypeString && r.Type != AttrTypeNumber && r.Type != AttrTypeEnum && r.Type != AttrTypeBool {
		return fmt.Errorf("type must be 'string', 'number', 'enum', or 'bool'")
	}
	if r.ManagedBy == "" {
		return fmt.Errorf("managed_by is required")
	}
	if len(r.Operators) == 0 {
		return fmt.Errorf("operators is required and must not be empty")
	}
	for _, op := range r.Operators {
		if !ValidOperators[op] {
			return fmt.Errorf("invalid operator: %s", op)
		}
	}
	if r.Type == AttrTypeEnum && len(r.AllowedValues) == 0 {
		return fmt.Errorf("allowed_values is required for enum type")
	}
	return nil
}

// PolicyRuleFilter is used to filter policy rules
type PolicyRuleFilter struct {
	ResourceType string
	Action       string
	Enabled      *bool
}

// SubjectFilter is used to filter subjects
type SubjectFilter struct {
	UserID  string
	Role    string
	Status  string
	GroupID string
}
