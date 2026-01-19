package adapter

import (
	"context"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/repository"
)

// LocalRelationAdapter implements RelationAdapter using local MongoDB repository
type LocalRelationAdapter struct {
	repo repository.RBACRepository
}

// NewLocalRelationAdapter creates a new LocalRelationAdapter
func NewLocalRelationAdapter(repo repository.RBACRepository) *LocalRelationAdapter {
	return &LocalRelationAdapter{repo: repo}
}

// CreateRelation creates a new relation by upserting a user role
func (a *LocalRelationAdapter) CreateRelation(ctx context.Context, req *RelationRequest) error {
	role := a.toUserRole(req)
	return a.repo.UpsertUserRole(ctx, role)
}

// DeleteRelation removes an existing relation
func (a *LocalRelationAdapter) DeleteRelation(ctx context.Context, req *RelationRequest) error {
	// Determine scope based on resource_type
	scope := a.determineScope(req.ResourceType)

	// For system scope, resource_id is used as namespace
	namespace := ""
	resourceID := req.ResourceID
	if scope == model.ScopeSystem {
		namespace = req.ResourceID
		resourceID = ""
	}

	return a.repo.DeleteUserRole(ctx, namespace, req.UserID, scope, resourceID, req.ResourceType, "")
}

// CheckRelation checks if a relation exists
func (a *LocalRelationAdapter) CheckRelation(ctx context.Context, req *RelationRequest) (bool, error) {
	scope := a.determineScope(req.ResourceType)

	if scope == model.ScopeSystem {
		// For system scope, resource_id is treated as namespace
		return a.repo.HasSystemRole(ctx, req.UserID, req.ResourceID, req.Relation)
	}

	return a.repo.HasResourceRole(ctx, req.UserID, req.ResourceID, req.ResourceType, req.Relation)
}

// BulkCreateRelations creates multiple relations in a batch
func (a *LocalRelationAdapter) BulkCreateRelations(ctx context.Context, reqs []*RelationRequest) (*BulkRelationResult, error) {
	if len(reqs) == 0 {
		return &BulkRelationResult{SuccessCount: 0, FailedCount: 0}, nil
	}

	// Convert to UserRoles
	roles := make([]*model.UserRole, len(reqs))
	for i, req := range reqs {
		roles[i] = a.toUserRole(req)
	}

	// Call bulk upsert
	result, err := a.repo.BulkUpsertUserRoles(ctx, roles)
	if err != nil {
		return nil, err
	}

	// Convert result
	bulkResult := &BulkRelationResult{
		SuccessCount: result.SuccessCount,
		FailedCount:  result.FailedCount,
	}

	for _, failed := range result.FailedUsers {
		bulkResult.FailedItems = append(bulkResult.FailedItems, FailedRelationItem{
			UserID: failed.UserID,
			Reason: failed.Reason,
		})
	}

	return bulkResult, nil
}

// toUserRole converts a RelationRequest to a UserRole
func (a *LocalRelationAdapter) toUserRole(req *RelationRequest) *model.UserRole {
	scope := a.determineScope(req.ResourceType)

	role := &model.UserRole{
		UserID:       req.UserID,
		UserType:     req.UserType,
		Role:         req.Relation, // relation maps to role
		Scope:        scope,
		ResourceType: req.ResourceType,
	}

	if scope == model.ScopeSystem {
		// For system scope, resource_id is treated as namespace
		role.Namespace = req.ResourceID
	} else {
		role.ResourceID = req.ResourceID
	}

	return role
}

// determineScope determines the scope based on resource type
func (a *LocalRelationAdapter) determineScope(resourceType string) string {
	// System-level resource types
	switch resourceType {
	case "system", "namespace", "platform":
		return model.ScopeSystem
	default:
		return model.ScopeResource
	}
}
