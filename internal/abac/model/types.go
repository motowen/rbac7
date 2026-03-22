package model

import "time"

// --- Subject (managed by ABAC service, stored in DB) ---

// OrgMembership represents a user's membership in an organization
type OrgMembership struct {
	OrgID   string `json:"org_id" bson:"org_id"`
	OrgType string `json:"org_type" bson:"org_type"`
}

// CustomAttr is a key-value pair for custom attributes
type CustomAttr struct {
	Key   string      `json:"key" bson:"key"`
	Value interface{} `json:"value" bson:"value"`
}

// Subject represents a user with all their attributes
type Subject struct {
	ID               string          `bson:"_id,omitempty"`
	UserID           string          `json:"user_id" bson:"user_id"`
	Role             string          `json:"role" bson:"role"`
	Status           string          `json:"status" bson:"status"`
	SensitivityLevel string          `json:"sensitivity_level" bson:"sensitivity_level"`
	Orgs             []OrgMembership `json:"orgs" bson:"orgs"`
	GroupIDs         []string        `json:"group_ids" bson:"group_ids"`
	CustomAttrs      []CustomAttr    `json:"custom_attrs" bson:"custom_attrs"`

	// Audit Fields
	CreatedAt time.Time  `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" bson:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" bson:"deleted_at,omitempty"`
	CreatedBy string     `json:"created_by,omitempty" bson:"created_by,omitempty"`
	UpdatedBy string     `json:"updated_by,omitempty" bson:"updated_by,omitempty"`
}

// --- Resource (NOT stored in DB, passed in by caller) ---

// ResourceAttrs represents resource attributes provided by the caller
type ResourceAttrs struct {
	ResourceID       string       `json:"resource_id"`
	ResourceType     string       `json:"resource_type"`
	ResourceParentID string       `json:"resource_parent_id,omitempty"`
	OwnerID          string       `json:"owner_id,omitempty"`
	SensitivityLevel string       `json:"sensitivity_level,omitempty"`
	Status           string       `json:"status,omitempty"`
	AllowedGroupIDs  []string     `json:"allowed_group_ids,omitempty"`
	DeniedGroupIDs   []string     `json:"denied_group_ids,omitempty"`
	ResourceGroupIDs []string     `json:"resource_group_ids,omitempty"`
	CustomAttrs      []CustomAttr `json:"custom_attrs,omitempty"`
}

// --- Policy Rule (stored in DB, dynamically managed) ---

// Condition represents a single condition for rule evaluation
type Condition struct {
	Field    string      `json:"field" bson:"field"`       // e.g. "role", "status", "sensitivity_level", "custom.team"
	Operator string      `json:"operator" bson:"operator"` // eq, neq, in, not_in, gt, gte, lt, lte, contains
	Value    interface{} `json:"value" bson:"value"`       // expected value (string, number, []string, etc.)
}

// ConditionSet groups subject and resource conditions
type ConditionSet struct {
	Subject  []Condition `json:"subject,omitempty" bson:"subject,omitempty"`
	Resource []Condition `json:"resource,omitempty" bson:"resource,omitempty"`
}

// PolicyRule defines an access control rule
type PolicyRule struct {
	ID           string       `json:"id" bson:"_id,omitempty"`
	Name         string       `json:"name" bson:"name"`
	Description  string       `json:"description,omitempty" bson:"description,omitempty"`
	ResourceType string       `json:"resource_type" bson:"resource_type"` // e.g. "docs", "dashboard"
	Action       string       `json:"action" bson:"action"`               // e.g. "read", "update", "delete"
	Effect       string       `json:"effect" bson:"effect"`               // "allow" or "deny"
	Priority     int          `json:"priority" bson:"priority"`           // higher = evaluated first
	Conditions   ConditionSet `json:"conditions" bson:"conditions"`
	Enabled      bool         `json:"enabled" bson:"enabled"`

	// Audit Fields
	CreatedAt time.Time  `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" bson:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" bson:"deleted_at,omitempty"`
	CreatedBy string     `json:"created_by,omitempty" bson:"created_by,omitempty"`
	UpdatedBy string     `json:"updated_by,omitempty" bson:"updated_by,omitempty"`
}

// --- Attribute Definition ---

// AttributeDefinition defines the schema for a custom attribute
type AttributeDefinition struct {
	ID            string   `json:"id" bson:"_id,omitempty"`
	Key           string   `json:"key" bson:"key"`                       // e.g. "doc.sensitivity"
	Scope         string   `json:"scope" bson:"scope"`                   // "subject" or "resource"
	ResourceType  string   `json:"resource_type,omitempty" bson:"resource_type,omitempty"` // applicable resource type
	Type          string   `json:"type" bson:"type"`                     // "string", "number", "enum", "bool"
	ManagedBy     string   `json:"managed_by" bson:"managed_by"`         // "app", "admin", etc.
	Operators     []string `json:"operators" bson:"operators"`           // supported operators
	AllowedValues []string `json:"allowed_values,omitempty" bson:"allowed_values,omitempty"` // for enum type

	// Audit Fields
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
	CreatedBy string    `json:"created_by,omitempty" bson:"created_by,omitempty"`
}

// --- Error Response ---

// ErrorResponse for consistent error handling
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail provides error details
type ErrorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

// Error implements error interface
func (e *ErrorDetail) Error() string {
	return e.Message
}

// --- Check Access Response ---

// CheckAccessResponse is the response for access check
type CheckAccessResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// BatchCheckAccessResponse is the response for batch access check
type BatchCheckAccessResponse struct {
	Results map[string]CheckAccessResponse `json:"results"` // key = resource_id
}
