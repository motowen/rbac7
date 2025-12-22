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
}

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

func (r *MongoRepository) TransferSystemOwner(ctx context.Context, namespace, oldOwnerID, newOwnerID, updatedBy string) error {
	session, err := r.Client.StartSession()
	if err != nil {
		return err
	}
	defer session.EndSession(ctx)

	callback := func(sessCtx mongo.SessionContext) (interface{}, error) {
		// 1. Demote Old Owner to Admin
		filterOld := bson.M{
			"user_id":    oldOwnerID,
			"user_type":  model.UserTypeMember,
			"scope":      model.ScopeSystem,
			"namespace":  namespace,
			"role":       model.RoleSystemOwner,
			"deleted_at": nil,
		}

		now := time.Now()

		updateOld := bson.M{
			"$set": bson.M{
				"role":       model.RoleSystemAdmin,
				"updated_at": now,
				"updated_by": updatedBy,
			},
		}

		resOld, err := r.SystemRoles.UpdateOne(sessCtx, filterOld, updateOld)
		if err != nil {
			return nil, err
		}
		if resOld.MatchedCount == 0 {
			// Could happen if race condition or old owner removed
			return nil, errors.New("current owner not found or role changed")
		}

		// 2. Promote New Owner (Upsert to handle if they are already a member or not)
		filterNew := bson.M{
			"user_id":   newOwnerID,
			"user_type": model.UserTypeMember,
			"scope":     model.ScopeSystem,
			"namespace": namespace,
		}
		updateNew := bson.M{
			"$set": bson.M{
				"role":       model.RoleSystemOwner,
				"user_type":  model.UserTypeMember,
				"updated_at": now,
				"updated_by": updatedBy,
			},
			"$setOnInsert": bson.M{
				"created_at": now,
				"created_by": updatedBy,
			},
			"$unset": bson.M{
				"deleted_at": "",
				"deleted_by": "",
			},
		}
		opts := options.Update().SetUpsert(true)

		_, err = r.SystemRoles.UpdateOne(sessCtx, filterNew, updateNew, opts)
		if err != nil {
			return nil, err
		}

		return nil, nil
	}

	_, err = session.WithTransaction(ctx, callback)
	return err
}

func (r *MongoRepository) TransferResourceOwner(ctx context.Context, resourceID, resourceType, oldOwnerID, newOwnerID, updatedBy string) error {
	session, err := r.Client.StartSession()
	if err != nil {
		return err
	}
	defer session.EndSession(ctx)

	callback := func(sessCtx mongo.SessionContext) (interface{}, error) {
		// 1. Demote Old Owner to Admin
		filterOld := bson.M{
			"user_id":       oldOwnerID,
			"user_type":     model.UserTypeMember,
			"scope":         model.ScopeResource,
			"resource_id":   resourceID,
			"resource_type": resourceType,
			"role":          model.RoleResourceOwner,
			"deleted_at":    nil,
		}

		now := time.Now()
		updateOld := bson.M{
			"$set": bson.M{
				"role":       model.RoleResourceAdmin,
				"updated_at": now,
				"updated_by": updatedBy,
			},
		}

		resOld, err := r.ResourceRoles.UpdateOne(sessCtx, filterOld, updateOld)
		if err != nil {
			return nil, err
		}
		if resOld.MatchedCount == 0 {
			return nil, errors.New("current resource owner not found or role changed")
		}

		// 2. Promote New Owner
		filterNew := bson.M{
			"user_id":       newOwnerID,
			"user_type":     model.UserTypeMember,
			"scope":         model.ScopeResource,
			"resource_id":   resourceID,
			"resource_type": resourceType,
		}
		updateNew := bson.M{
			"$set": bson.M{
				"role":          model.RoleResourceOwner,
				"user_type":     model.UserTypeMember,
				"updated_at":    now,
				"updated_by":    updatedBy,
				"scope":         model.ScopeResource,
				"resource_id":   resourceID,
				"resource_type": resourceType,
			},
			"$setOnInsert": bson.M{
				"created_at": now,
				"created_by": updatedBy,
			},
			"$unset": bson.M{
				"deleted_at": "",
				"deleted_by": "",
			},
		}
		opts := options.Update().SetUpsert(true)

		_, err = r.ResourceRoles.UpdateOne(sessCtx, filterNew, updateNew, opts)
		if err != nil {
			return nil, err
		}

		return nil, nil
	}

	_, err = session.WithTransaction(ctx, callback)
	return err
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

func (r *MongoRepository) GetSystemOwner(ctx context.Context, namespace string) (*model.UserRole, error) {
	filter := bson.M{
		"scope":      model.ScopeSystem,
		"namespace":  namespace,
		"role":       model.RoleSystemOwner,
		"deleted_at": nil,
	}
	var role model.UserRole
	err := r.SystemRoles.FindOne(ctx, filter).Decode(&role)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &role, nil
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

func (r *MongoRepository) CountSystemOwners(ctx context.Context, namespace string) (int64, error) {
	filter := bson.M{
		"scope":      model.ScopeSystem,
		"namespace":  namespace,
		"role":       model.RoleSystemOwner,
		"deleted_at": nil,
	}
	return r.SystemRoles.CountDocuments(ctx, filter)
}

func (r *MongoRepository) CountResourceOwners(ctx context.Context, resourceID, resourceType string) (int64, error) {
	filter := bson.M{
		"scope":         model.ScopeResource,
		"resource_id":   resourceID,
		"resource_type": resourceType,
		"role":          model.RoleResourceOwner,
		"deleted_at":    nil,
	}
	return r.ResourceRoles.CountDocuments(ctx, filter)
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
