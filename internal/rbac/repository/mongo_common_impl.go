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

type MongoRepository struct {
	SystemRoles   *mongo.Collection
	ResourceRoles *mongo.Collection
	Client        *mongo.Client // Added Client for transactions
}

func NewMongoRepository(db *mongo.Database, systemCollectionName, resourceCollectionName string) *MongoRepository {
	repo := &MongoRepository{
		SystemRoles:   db.Collection(systemCollectionName),
		ResourceRoles: db.Collection(resourceCollectionName),
		Client:        db.Client(),
	}
	return repo
}

func (r *MongoRepository) EnsureIndexes(ctx context.Context) error {
	// 1. System Roles Index: (user_id, user_type, scope, namespace) unique
	// "uniq_user_per_namespace_scope"
	idxSystemUnique := mongo.IndexModel{
		Keys: bson.D{
			{Key: "user_id", Value: 1},
			{Key: "user_type", Value: 1},
			{Key: "scope", Value: 1},
			{Key: "namespace", Value: 1},
		},
		Options: options.Index().SetUnique(true).SetName("uniq_user_per_namespace_scope"),
	}

	// 2. System Owner Index: (scope, namespace, role) unique where role="owner"
	idxSystemOwner := mongo.IndexModel{
		Keys: bson.D{
			{Key: "scope", Value: 1},
			{Key: "namespace", Value: 1},
		},
		Options: options.Index().
			SetUnique(true).
			SetName("unique_system_owner_v2").
			SetPartialFilterExpression(bson.M{
				"scope":      model.ScopeSystem,
				"role":       model.RoleSystemOwner,
				"deleted_at": nil,
			}),
	}

	_, err := r.SystemRoles.Indexes().CreateMany(ctx, []mongo.IndexModel{idxSystemUnique, idxSystemOwner})
	if err != nil {
		return err
	}

	// 3. Resource Roles Index: (user_id, user_type, scope, resource_type, resource_id) unique
	// "uniq_user_per_resource_scope"
	idxResourceUnique := mongo.IndexModel{
		Keys: bson.D{
			{Key: "user_id", Value: 1},
			{Key: "user_type", Value: 1},
			{Key: "scope", Value: 1},
			{Key: "resource_type", Value: 1},
			{Key: "resource_id", Value: 1},
		},
		Options: options.Index().SetUnique(true).SetName("uniq_user_per_resource_scope"),
	}

	// 4. Resource Owner Unique Index
	idxResourceOwner := mongo.IndexModel{
		Keys: bson.D{
			{Key: "scope", Value: 1},
			{Key: "resource_id", Value: 1},
			{Key: "resource_type", Value: 1},
		},
		Options: options.Index().
			SetUnique(true).
			SetName("unique_resource_owner").
			SetPartialFilterExpression(bson.M{
				"scope":      model.ScopeResource,
				"role":       model.RoleResourceOwner,
				"deleted_at": nil,
			}),
	}

	_, err = r.ResourceRoles.Indexes().CreateMany(ctx, []mongo.IndexModel{idxResourceUnique, idxResourceOwner})
	return err
}

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
