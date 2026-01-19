package adapter

import (
	"context"
)

// RelationRequest represents a uniform relation operation request
// This structure matches the external ReBAC API payload format
type RelationRequest struct {
	UserID       string `json:"user_id"`
	UserType     string `json:"user_type"`
	Relation     string `json:"relation"` // maps to "role" in local RBAC
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
}

// BulkRelationResult represents the result of a bulk relation operation
type BulkRelationResult struct {
	SuccessCount int                  `json:"success_count"`
	FailedCount  int                  `json:"failed_count"`
	FailedItems  []FailedRelationItem `json:"failed_items,omitempty"`
}

// FailedRelationItem represents a failed item in bulk operation
type FailedRelationItem struct {
	UserID string `json:"user_id"`
	Reason string `json:"reason"`
}

// RelationAdapter defines the interface for relation operations
// This abstraction allows switching between local RBAC and external ReBAC systems
type RelationAdapter interface {
	// CreateRelation creates a new relation (assigns a role to a user on a resource)
	CreateRelation(ctx context.Context, req *RelationRequest) error

	// DeleteRelation removes an existing relation
	DeleteRelation(ctx context.Context, req *RelationRequest) error

	// CheckRelation checks if a relation exists
	CheckRelation(ctx context.Context, req *RelationRequest) (bool, error)

	// BulkCreateRelations creates multiple relations in a batch
	BulkCreateRelations(ctx context.Context, reqs []*RelationRequest) (*BulkRelationResult, error)
}
