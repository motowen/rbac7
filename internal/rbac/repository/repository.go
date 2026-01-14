package repository

import (
	"context"
	"errors"
	"rbac7/internal/rbac/model"
)

var ErrDuplicate = errors.New("duplicate record")

type RBACRepository interface {
	// Check if a system owner already exists for the namespace
	GetSystemOwner(ctx context.Context, namespace string) (*model.UserRole, error)
	// Create a new user role
	CreateUserRole(ctx context.Context, role *model.UserRole) error
	// Check if user has specific system role (ignoring namespace for now or just checking existence)
	HasSystemRole(ctx context.Context, userID, namespace, role string) (bool, error)
	// Check if user has ANY of the specified system roles
	HasAnySystemRole(ctx context.Context, userID, namespace string, roles []string) (bool, error)
	// Find user roles with filter
	FindUserRoles(ctx context.Context, filter model.UserRoleFilter) ([]*model.UserRole, error)
	// Initialize Indexes
	EnsureIndexes(ctx context.Context) error
	// Transfer ownership safely using transaction
	TransferSystemOwner(ctx context.Context, namespace, oldOwnerID, newOwnerID, updatedBy string) error
	// Upsert a user role (Create or Update)
	UpsertUserRole(ctx context.Context, role *model.UserRole) error
	// Delete a user role (Soft Delete)
	DeleteUserRole(ctx context.Context, namespace, userID, scope, resourceID, resourceType, deletedBy string) error
	// Count owners in a system
	CountSystemOwners(ctx context.Context, namespace string) (int64, error)
	// Count owners in a resource
	CountResourceOwners(ctx context.Context, resourceID, resourceType string) (int64, error)
	// Check if user has specific resource role
	HasResourceRole(ctx context.Context, userID, resourceID, resourceType, role string) (bool, error)
	// Check if user has ANY of the specified resource roles
	HasAnyResourceRole(ctx context.Context, userID, resourceID, resourceType string, roles []string) (bool, error)
	// Transfer resource ownership
	TransferResourceOwner(ctx context.Context, resourceID, resourceType, oldOwnerID, newOwnerID, updatedBy string) error
	// Count total roles assigned to a resource (used for whitelist check)
	CountResourceRoles(ctx context.Context, resourceID, resourceType string) (int64, error)
	// Bulk upsert user roles (partial success allowed)
	BulkUpsertUserRoles(ctx context.Context, roles []*model.UserRole) (*model.BatchUpsertResult, error)
	// Soft delete all user roles for a resource (including owner)
	SoftDeleteResourceUserRoles(ctx context.Context, req *model.SoftDeleteResourceReq, deletedBy string) error
}
