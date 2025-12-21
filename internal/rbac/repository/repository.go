package repository

import (
	"context"
	"errors"
	"rbac7/internal/rbac/model"

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
	TransferSystemOwner(ctx context.Context, namespace, oldOwnerID, newOwnerID string) error
	// Upsert a user role (Create or Update)
	UpsertUserRole(ctx context.Context, role *model.UserRole) error
	// Delete a user role
	DeleteUserRole(ctx context.Context, namespace, userID, scope string) error
	// Count owners in a system
	CountSystemOwners(ctx context.Context, namespace string) (int64, error)
}

type MongoRepository struct {
	Collection *mongo.Collection
	Client     *mongo.Client // Added Client for transactions
}

func NewMongoRepository(db *mongo.Database, collectionName string) *MongoRepository {
	repo := &MongoRepository{
		Collection: db.Collection(collectionName),
		Client:     db.Client(),
	}
	return repo
}

func (r *MongoRepository) TransferSystemOwner(ctx context.Context, namespace, oldOwnerID, newOwnerID string) error {
	session, err := r.Client.StartSession()
	if err != nil {
		return err
	}
	defer session.EndSession(ctx)

	callback := func(sessCtx mongo.SessionContext) (interface{}, error) {
		// 1. Demote Old Owner to Admin
		filterOld := bson.M{
			"user_id":   oldOwnerID,
			"scope":     model.ScopeSystem,
			"namespace": namespace,
			"role":      model.RoleSystemOwner,
		}
		updateOld := bson.M{"$set": bson.M{"role": model.RoleSystemAdmin}}

		resOld, err := r.Collection.UpdateOne(sessCtx, filterOld, updateOld)
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
			"scope":     model.ScopeSystem,
			"namespace": namespace,
		}
		updateNew := bson.M{
			"$set": bson.M{
				"role":      model.RoleSystemOwner,
				"user_type": model.UserTypeMember, // Ensure user type
			},
		}
		opts := options.Update().SetUpsert(true)

		_, err = r.Collection.UpdateOne(sessCtx, filterNew, updateNew, opts)
		if err != nil {
			return nil, err
		}

		return nil, nil
	}

	_, err = session.WithTransaction(ctx, callback)
	return err
}

func (r *MongoRepository) EnsureIndexes(ctx context.Context) error {
	// 1. (user_id, user_type, scope, namespace) unique
	// Removed role from key as per user request
	idx1 := mongo.IndexModel{
		Keys: bson.D{
			{Key: "user_id", Value: 1},
			{Key: "user_type", Value: 1},
			{Key: "scope", Value: 1},
			{Key: "namespace", Value: 1}, // bson:"namespace"
		},
		Options: options.Index().SetUnique(true).SetName("uniq_user_per_namespace_scope"),
	}

	// 2. (scope, namespace, role) where role="owner"
	// Partial index
	idx2 := mongo.IndexModel{
		Keys: bson.D{
			{Key: "scope", Value: 1},
			{Key: "namespace", Value: 1},
		},
		Options: options.Index().
			SetUnique(true).
			SetName("unique_system_owner").
			SetPartialFilterExpression(bson.M{
				"scope": model.ScopeSystem,
				"role":  model.RoleSystemOwner,
			}),
	}

	_, err := r.Collection.Indexes().CreateMany(ctx, []mongo.IndexModel{idx1, idx2})
	return err
}

func (r *MongoRepository) GetSystemOwner(ctx context.Context, namespace string) (*model.UserRole, error) {
	filter := bson.M{
		"scope":     model.ScopeSystem,
		"namespace": namespace,
		"role":      model.RoleSystemOwner,
	}
	var role model.UserRole
	err := r.Collection.FindOne(ctx, filter).Decode(&role)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &role, nil
}

func (r *MongoRepository) CreateUserRole(ctx context.Context, role *model.UserRole) error {
	_, err := r.Collection.InsertOne(ctx, role)
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
		"scope":     role.Scope,
		"namespace": role.Namespace, // Unique per user/scope/namespace
	}

	update := bson.M{"$set": role}
	opts := options.Update().SetUpsert(true)

	_, err := r.Collection.UpdateOne(ctx, filter, update, opts)
	return err
}

func (r *MongoRepository) DeleteUserRole(ctx context.Context, namespace, userID, scope string) error {
	filter := bson.M{
		"user_id":   userID,
		"scope":     scope,
		"namespace": namespace,
	}
	res, err := r.Collection.DeleteOne(ctx, filter)
	if err != nil {
		return err
	}
	if res.DeletedCount == 0 {
		return mongo.ErrNoDocuments // Or handle as success? handler expects 404 if not found?
	}
	return nil
}

func (r *MongoRepository) CountSystemOwners(ctx context.Context, namespace string) (int64, error) {
	filter := bson.M{
		"scope":     model.ScopeSystem,
		"namespace": namespace,
		"role":      model.RoleSystemOwner,
	}
	return r.Collection.CountDocuments(ctx, filter)
}

func (r *MongoRepository) HasSystemRole(ctx context.Context, userID, namespace, role string) (bool, error) {
	// For performance, we add limit 1
	opts := options.Count().SetLimit(1)
	filter := bson.M{
		"user_id": userID,
		"scope":   model.ScopeSystem,
		"role":    role,
	}
	if namespace != "" {
		filter["namespace"] = namespace
	}
	count, err := r.Collection.CountDocuments(ctx, filter, opts)
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
		"user_id": userID,
		"scope":   model.ScopeSystem,
		"role":    bson.M{"$in": roles},
	}
	if namespace != "" {
		filter["namespace"] = namespace
	}
	count, err := r.Collection.CountDocuments(ctx, filter, opts)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *MongoRepository) FindUserRoles(ctx context.Context, filter model.UserRoleFilter) ([]*model.UserRole, error) {
	query := bson.M{}
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

	cursor, err := r.Collection.Find(ctx, query)
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
