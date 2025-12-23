package repository

import (
	"context"
	"errors"
	"rbac7/internal/rbac/model"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func (r *MongoRepository) CreateUserRole(ctx context.Context, role *model.UserRole) error {
	role.CreatedAt = time.Now()
	role.UpdatedAt = time.Now()

	var coll *mongo.Collection
	if role.Scope == model.ScopeSystem {
		coll = r.SystemRoles
	} else if role.Scope == model.ScopeResource {
		coll = r.ResourceRoles
	} else {
		return errors.New("invalid scope")
	}

	_, err := coll.InsertOne(ctx, role)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return ErrDuplicate
		}
		return err
	}
	return nil
}

func (r *MongoRepository) UpsertUserRole(ctx context.Context, role *model.UserRole) error {
	filter := bson.M{
		"user_id":   role.UserID,
		"user_type": role.UserType,
		"scope":     role.Scope,
	}
	// Add scope specific fields to filter
	if role.Scope == model.ScopeSystem {
		filter["namespace"] = role.Namespace
	} else if role.Scope == model.ScopeResource {
		filter["resource_id"] = role.ResourceID
		filter["resource_type"] = role.ResourceType
		// Maybe namespace too? Requirement usually puts resource in namespace.
		// For unique index 'uniq_user_per_resource_scope', we use resource_id + resource_type.
		// Namespace might be metadata.
	}

	now := time.Now()
	role.UpdatedAt = now

	update := bson.M{
		"$set": bson.M{
			"role":          role.Role,
			"updated_at":    now,
			"updated_by":    role.UpdatedBy,
			"created_by":    role.CreatedBy,
			"namespace":     role.Namespace, // Ensure these are set
			"resource_id":   role.ResourceID,
			"resource_type": role.ResourceType,
		},
		"$setOnInsert": bson.M{
			"created_at": now,
			"user_id":    role.UserID,
			"user_type":  role.UserType,
			"scope":      role.Scope,
		},
		"$unset": bson.M{
			"deleted_at": "",
			"deleted_by": "",
		},
	}
	opts := options.Update().SetUpsert(true)

	var coll *mongo.Collection
	if role.Scope == model.ScopeSystem {
		coll = r.SystemRoles
	} else {
		coll = r.ResourceRoles
	}

	_, err := coll.UpdateOne(ctx, filter, update, opts)
	return err
}

func (r *MongoRepository) DeleteUserRole(ctx context.Context, namespace, userID, scope, resourceID, resourceType, deletedBy string) error {
	filter := bson.M{
		"user_id":    userID,
		"scope":      scope,
		"deleted_at": nil,
	}

	var coll *mongo.Collection

	if scope == model.ScopeSystem {
		coll = r.SystemRoles
		filter["namespace"] = namespace
	} else if scope == model.ScopeResource {
		coll = r.ResourceRoles
		// For resource roles, we use resource_id + resource_type as composite key usually?
		// Or do we strictly follow user input?
		if resourceID != "" {
			filter["resource_id"] = resourceID
		}
		if resourceType != "" {
			filter["resource_type"] = resourceType
		}
		// Namespace might be optional context or part of query?
		if namespace != "" {
			filter["namespace"] = namespace
		}
	} else {
		return errors.New("invalid scope")
	}

	update := bson.M{
		"$set": bson.M{
			"deleted_at": time.Now(),
			"deleted_by": deletedBy,
		},
	}
	res, err := coll.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return mongo.ErrNoDocuments
	}
	return nil
}

func (r *MongoRepository) FindUserRoles(ctx context.Context, filter model.UserRoleFilter) ([]*model.UserRole, error) {
	query := bson.M{
		"deleted_at": nil,
	}
	if filter.UserID != "" {
		query["user_id"] = filter.UserID
	}
	if filter.Namespace != "" {
		query["namespace"] = filter.Namespace
	}
	if filter.Role != "" {
		query["role"] = filter.Role
	}
	if filter.Scope != "" {
		query["scope"] = filter.Scope
	}
	if filter.ResourceID != "" {
		query["resource_id"] = filter.ResourceID
	}
	if filter.ResourceType != "" {
		query["resource_type"] = filter.ResourceType
	}

	// Logic: If scope is strict, query that one.
	// If filter.Scope is empty, we must query BOTH and merge.
	// API usually enforces scope for specific listings, but GetUserRoles might not?

	if filter.Scope == model.ScopeSystem {
		cursor, err := r.SystemRoles.Find(ctx, query)
		if err != nil {
			return nil, err
		}
		defer cursor.Close(ctx)
		var roles []*model.UserRole
		if err = cursor.All(ctx, &roles); err != nil {
			return nil, err
		}
		return roles, nil
	} else if filter.Scope == model.ScopeResource {
		cursor, err := r.ResourceRoles.Find(ctx, query)
		if err != nil {
			return nil, err
		}
		defer cursor.Close(ctx)
		var roles []*model.UserRole
		if err = cursor.All(ctx, &roles); err != nil {
			return nil, err
		}
		return roles, nil
	}

	// If no scope specified, query both
	var allRoles []*model.UserRole

	// System
	cursorSys, err := r.SystemRoles.Find(ctx, query)
	if err == nil {
		var roles []*model.UserRole
		_ = cursorSys.All(ctx, &roles)
		cursorSys.Close(ctx)
		allRoles = append(allRoles, roles...)
	}

	// Resource
	cursorRes, err := r.ResourceRoles.Find(ctx, query)
	if err == nil {
		var roles []*model.UserRole
		_ = cursorRes.All(ctx, &roles)
		cursorRes.Close(ctx)
		allRoles = append(allRoles, roles...)
	}

	return allRoles, nil
}

func (r *MongoRepository) HasResourceRole(ctx context.Context, userID, resourceID, resourceType, role string) (bool, error) {
	opts := options.Count().SetLimit(1)
	filter := bson.M{
		"user_id":       userID,
		"scope":         model.ScopeResource,
		"role":          role,
		"deleted_at":    nil,
		"resource_id":   resourceID,
		"resource_type": resourceType,
	}
	count, err := r.ResourceRoles.CountDocuments(ctx, filter, opts)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *MongoRepository) HasAnyResourceRole(ctx context.Context, userID, resourceID, resourceType string, roles []string) (bool, error) {
	if len(roles) == 0 {
		return false, nil
	}
	opts := options.Count().SetLimit(1)
	filter := bson.M{
		"user_id":       userID,
		"scope":         model.ScopeResource,
		"role":          bson.M{"$in": roles},
		"deleted_at":    nil,
		"resource_id":   resourceID,
		"resource_type": resourceType,
	}
	count, err := r.ResourceRoles.CountDocuments(ctx, filter, opts)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *MongoRepository) HasSystemRole(ctx context.Context, userID, namespace, role string) (bool, error) {
	// For performance, we add limit 1
	opts := options.Count().SetLimit(1)
	filter := bson.M{
		"user_id":    userID,
		"scope":      model.ScopeSystem,
		"role":       role,
		"deleted_at": nil,
	}
	if namespace != "" {
		filter["namespace"] = namespace
	}
	count, err := r.SystemRoles.CountDocuments(ctx, filter, opts)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *MongoRepository) HasAnySystemRole(ctx context.Context, userID, namespace string, roles []string) (bool, error) {
	if len(roles) == 0 {
		return false, nil
	}
	opts := options.Count().SetLimit(1)
	filter := bson.M{
		"user_id":    userID,
		"scope":      model.ScopeSystem,
		"role":       bson.M{"$in": roles},
		"deleted_at": nil,
	}
	if namespace != "" {
		filter["namespace"] = namespace
	}
	count, err := r.SystemRoles.CountDocuments(ctx, filter, opts)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
