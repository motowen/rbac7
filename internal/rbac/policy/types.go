package policy

// CheckScope defines how to check the permission
type CheckScope string

const (
	CheckScopeNone           CheckScope = "none"            // No permission check needed
	CheckScopeSystem         CheckScope = "system"          // Check against system namespace
	CheckScopeResource       CheckScope = "resource"        // Check against resource
	CheckScopeParentResource CheckScope = "parent_resource" // Check against parent resource
	CheckScopeSelfRoles      CheckScope = "self_roles"      // Check against caller's own roles
	CheckScopeGlobal         CheckScope = "global"          // Check against global roles (no namespace)
)

// OperationPolicy defines the permission requirements for an operation
type OperationPolicy struct {
	// API routing fields (for middleware)
	Method    string            `json:"method,omitempty"`    // HTTP method: GET, POST, PUT, DELETE
	Path      string            `json:"path,omitempty"`      // API path: /api/v1/user_roles
	Params    map[string]string `json:"params,omitempty"`    // Param extraction: {"namespace": "body.namespace"}
	Condition map[string]string `json:"condition,omitempty"` // Matching condition: {"scope": "system"}

	// Permission fields
	Permission             string     `json:"permission"`
	CheckScope             CheckScope `json:"check_scope"`
	NamespaceRequired      bool       `json:"namespace_required,omitempty"`
	ResourceIDRequired     bool       `json:"resource_id_required,omitempty"`
	ParentResourceRequired bool       `json:"parent_resource_required,omitempty"`
}

// EntityPolicy defines all operations for an entity
type EntityPolicy struct {
	Entity       string                      `json:"entity"`
	Scope        string                      `json:"scope"` // "system" or "resource"
	ParentEntity string                      `json:"parent_entity,omitempty"`
	Operations   map[string]*OperationPolicy `json:"operations"`
}

// CheckPermissionRule defines inheritance/fallback logic for permission checking
type CheckPermissionRule struct {
	Inheritance       string            `json:"inheritance"` // "none", "parent_if_no_roles"
	ParentType        string            `json:"parent_type,omitempty"`
	PermissionMapping map[string]string `json:"permission_mapping,omitempty"`
}

// CheckPermissionConfig defines rules for the CheckPermission API
type CheckPermissionConfig struct {
	ResourceTypes map[string]*CheckPermissionRule `json:"resource_types"`
}

// RolePermissions maps role names to their permissions
type RolePermissions map[string][]string

// OperationRequest is the input for checking operation permission
type OperationRequest struct {
	CallerID         string
	Entity           string // "system", "dashboard", "library_widget", etc. - can be inferred from Scope/ResourceType
	Operation        string // "assign_owner", "get_members", etc. - can be auto-adjusted for viewer operations
	Scope            string // "system" or "resource" - used to infer Entity if not provided
	Namespace        string
	ResourceID       string
	ResourceType     string
	ParentResourceID string
	Role             string // Target role - used to auto-detect viewer operations (e.g., "viewer" triggers widget-specific handling)
}

// APIConfig represents a single API endpoint configuration for middleware matching
type APIConfig struct {
	Entity    string           // Entity name (system, dashboard, etc.)
	Operation string           // Operation name (assign_owner, get_members, etc.)
	Policy    *OperationPolicy // Full policy including permission, check_scope, params
}
