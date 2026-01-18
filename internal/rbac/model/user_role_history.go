package model

import "time"

// UserRoleHistory 審計日誌記錄 (append-only, read-only after creation)
type UserRoleHistory struct {
	ID        string `bson:"_id,omitempty" json:"id"`
	Operation string `bson:"operation" json:"operation"` // assign_owner, transfer_owner, assign_user_role, assign_user_roles_batch, delete_user_role, delete_resource
	CallerID  string `bson:"caller_id" json:"caller_id"`

	// Scope Info
	Scope     string `bson:"scope" json:"scope"` // system/resource
	Namespace string `bson:"namespace,omitempty" json:"namespace,omitempty"`

	// Resource Info
	ResourceID       string `bson:"resource_id,omitempty" json:"resource_id,omitempty"`
	ResourceType     string `bson:"resource_type,omitempty" json:"resource_type,omitempty"`
	ParentResourceID string `bson:"parent_resource_id,omitempty" json:"parent_resource_id,omitempty"`

	// Target User Info
	UserID   string   `bson:"user_id,omitempty" json:"user_id,omitempty"`   // 單一操作
	UserIDs  []string `bson:"user_ids,omitempty" json:"user_ids,omitempty"` // 批次操作
	UserType string   `bson:"user_type,omitempty" json:"user_type,omitempty"`

	// Role Info
	Role       string `bson:"role,omitempty" json:"role,omitempty"`
	NewOwnerID string `bson:"new_owner_id,omitempty" json:"new_owner_id,omitempty"` // transfer_owner

	// Soft Delete Info (for delete_resource)
	ChildResourceIDs []string `bson:"child_resource_ids,omitempty" json:"child_resource_ids,omitempty"`

	// Timestamp
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
}
