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
	History       *mongo.Collection
	Client        *mongo.Client // Added Client for transactions
}

func NewMongoRepository(db *mongo.Database, systemCollectionName, resourceCollectionName string) *MongoRepository {
	repo := &MongoRepository{
		SystemRoles:   db.Collection(systemCollectionName),
		ResourceRoles: db.Collection(resourceCollectionName),
		History:       db.Collection("user_role_history"),
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
		"role":      bson.M{"$ne": model.RoleSystemOwner}, // Protect owner role
	}
	// Add scope specific fields to filter
	if role.Scope == model.ScopeSystem {
		filter["namespace"] = role.Namespace
	} else if role.Scope == model.ScopeResource {
		filter["resource_id"] = role.ResourceID
		filter["resource_type"] = role.ResourceType
		// For resource scope, also protect resource owner if needed
		if role.Scope == model.ScopeResource {
			filter["role"] = bson.M{"$ne": model.RoleResourceOwner}
		}
	}

	now := time.Now()
	role.UpdatedAt = now

	update := bson.M{
		"$set": bson.M{
			"role":          role.Role,
			"updated_at":    now,
			"updated_by":    role.UpdatedBy,
			"created_by":    role.CreatedBy,
			"namespace":     role.Namespace,
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

func (r *MongoRepository) BulkUpsertUserRoles(ctx context.Context, roles []*model.UserRole) (*model.BatchUpsertResult, error) {
	if len(roles) == 0 {
		return &model.BatchUpsertResult{SuccessCount: 0, FailedCount: 0}, nil
	}

	// Assume all roles have the same scope for batch operation
	scope := roles[0].Scope
	var coll *mongo.Collection
	if scope == model.ScopeSystem {
		coll = r.SystemRoles
	} else {
		coll = r.ResourceRoles
	}

	now := time.Now()

	writeModels := make([]mongo.WriteModel, 0, len(roles))
	for _, role := range roles {
		role.UpdatedAt = now

		filter := bson.M{
			"user_id":   role.UserID,
			"user_type": role.UserType,
			"scope":     role.Scope,
			"role":      bson.M{"$ne": model.RoleSystemOwner}, // Protect owner role
		}
		if scope == model.ScopeSystem {
			filter["namespace"] = role.Namespace
		} else {
			filter["resource_id"] = role.ResourceID
			filter["resource_type"] = role.ResourceType
			filter["role"] = bson.M{"$ne": model.RoleResourceOwner}
		}

		update := bson.M{
			"$set": bson.M{
				"role":          role.Role,
				"updated_at":    now,
				"updated_by":    role.UpdatedBy,
				"created_by":    role.CreatedBy,
				"namespace":     role.Namespace,
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

		writeModel := mongo.NewUpdateOneModel().
			SetFilter(filter).
			SetUpdate(update).
			SetUpsert(true)
		writeModels = append(writeModels, writeModel)
	}

	// Ordered: false allows partial success
	opts := options.BulkWrite().SetOrdered(false)
	_, err := coll.BulkWrite(ctx, writeModels, opts)

	batchResult := &model.BatchUpsertResult{
		SuccessCount: 0,
		FailedCount:  0,
		FailedUsers:  []model.FailedUserInfo{},
	}

	if err != nil {
		// Check for bulk write exception to get partial results
		if bulkErr, ok := err.(mongo.BulkWriteException); ok {
			// Count successes: total - failed
			totalOps := len(roles)
			failedOps := len(bulkErr.WriteErrors)
			batchResult.SuccessCount = totalOps - failedOps
			batchResult.FailedCount = failedOps

			for _, writeErr := range bulkErr.WriteErrors {
				idx := writeErr.Index
				if idx >= 0 && idx < len(roles) {
					batchResult.FailedUsers = append(batchResult.FailedUsers, model.FailedUserInfo{
						UserID: roles[idx].UserID,
						Reason: writeErr.Message,
					})
				}
			}
			return batchResult, nil // Partial success, no error returned
		}
		// Other errors (connection issues, etc.)
		return nil, err
	}

	// All succeeded
	if batchResult.SuccessCount == 0 {
		batchResult.SuccessCount = len(roles)
	}

	return batchResult, nil
}

func (r *MongoRepository) DeleteUserRole(ctx context.Context, namespace, userID, scope, resourceID, resourceType, deletedBy string) error {
	filter := bson.M{
		"user_id":    userID,
		"scope":      scope,
		"deleted_at": nil,
		"role":       bson.M{"$ne": model.RoleSystemOwner}, // Protect owner role
	}

	var coll *mongo.Collection

	if scope == model.ScopeSystem {
		coll = r.SystemRoles
		filter["namespace"] = namespace
	} else if scope == model.ScopeResource {
		coll = r.ResourceRoles
		filter["role"] = bson.M{"$ne": model.RoleResourceOwner} // Protect resource owner

		if resourceID != "" {
			filter["resource_id"] = resourceID
		}
		if resourceType != "" {
			filter["resource_type"] = resourceType
		}
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

// SoftDeleteResourceUserRoles soft deletes all user roles for a resource (including owner).
// This is used when deleting a resource entirely.
// For dashboard: also deletes all child widget user roles.
func (r *MongoRepository) SoftDeleteResourceUserRoles(ctx context.Context, req *model.SoftDeleteResourceReq, deletedBy string) error {
	now := time.Now()
	update := bson.M{
		"$set": bson.M{
			"deleted_at": now,
			"deleted_by": deletedBy,
		},
	}

	// Collect all resource IDs to delete
	resourceIDs := []string{req.ResourceID}
	if len(req.ChildResourceIDs) > 0 {
		resourceIDs = append(resourceIDs, req.ChildResourceIDs...)
	}

	// Build filter based on resource type
	filter := bson.M{
		"resource_id": bson.M{"$in": resourceIDs},
		"scope":       model.ScopeResource,
		"deleted_at":  nil, // Only delete active roles
	}

	// For library_widget, also match namespace
	if req.ResourceType == "library_widget" && req.Namespace != "" {
		filter["namespace"] = req.Namespace
	}

	// Execute update (no owner protection - this deletes everything including owner)
	_, err := r.ResourceRoles.UpdateMany(ctx, filter, update)
	return err
}

// HistoryRepository implementation

// EnsureHistoryIndexes creates indexes for efficient history querying
func (r *MongoRepository) EnsureHistoryIndexes(ctx context.Context) error {
	indexes := []mongo.IndexModel{
		// System scope query: namespace + created_at
		{
			Keys: bson.D{
				{Key: "scope", Value: 1},
				{Key: "namespace", Value: 1},
				{Key: "created_at", Value: -1},
			},
			Options: options.Index().SetName("idx_system_scope_query"),
		},
		// Resource scope query: resource_id + resource_type + created_at
		{
			Keys: bson.D{
				{Key: "scope", Value: 1},
				{Key: "resource_id", Value: 1},
				{Key: "resource_type", Value: 1},
				{Key: "created_at", Value: -1},
			},
			Options: options.Index().SetName("idx_resource_scope_query"),
		},
		// Created at for time-based queries
		{
			Keys:    bson.D{{Key: "created_at", Value: -1}},
			Options: options.Index().SetName("idx_created_at"),
		},
	}

	_, err := r.History.Indexes().CreateMany(ctx, indexes)
	return err
}

// CreateHistory creates a new history record (append-only)
func (r *MongoRepository) CreateHistory(ctx context.Context, history *model.UserRoleHistory) error {
	if history.CreatedAt.IsZero() {
		history.CreatedAt = time.Now()
	}
	_, err := r.History.InsertOne(ctx, history)
	return err
}

// FindHistory finds history records with pagination and filtering
func (r *MongoRepository) FindHistory(ctx context.Context, req model.GetUserRoleHistoryReq) ([]*model.UserRoleHistory, int64, error) {
	filter := bson.M{"scope": req.Scope}

	// Add scope-specific filters
	if req.Scope == model.ScopeSystem {
		filter["namespace"] = req.Namespace
	} else if req.Scope == model.ScopeResource {
		filter["resource_id"] = req.ResourceID
		filter["resource_type"] = req.ResourceType
	}

	// Add time range filter
	if req.StartTime != nil || req.EndTime != nil {
		timeFilter := bson.M{}
		if req.StartTime != nil {
			timeFilter["$gte"] = *req.StartTime
		}
		if req.EndTime != nil {
			timeFilter["$lte"] = *req.EndTime
		}
		filter["created_at"] = timeFilter
	}

	// Count total records
	total, err := r.History.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, err
	}

	// Calculate skip for pagination
	skip := int64((req.Page - 1) * req.Size)

	// Find with pagination and sort by created_at desc
	findOptions := options.Find().
		SetSort(bson.D{{Key: "created_at", Value: -1}}).
		SetSkip(skip).
		SetLimit(int64(req.Size))

	cursor, err := r.History.Find(ctx, filter, findOptions)
	if err != nil {
		return nil, 0, err
	}
	defer cursor.Close(ctx)

	var results []*model.UserRoleHistory
	if err := cursor.All(ctx, &results); err != nil {
		return nil, 0, err
	}

	return results, total, nil
}
