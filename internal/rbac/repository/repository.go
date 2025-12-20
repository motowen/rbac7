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
	HasSystemRole(ctx context.Context, userID, role string) (bool, error)
	// Initialize Indexes
	EnsureIndexes(ctx context.Context) error
}

type MongoRepository struct {
	Collection *mongo.Collection
}

func NewMongoRepository(db *mongo.Database) *MongoRepository {
	repo := &MongoRepository{
		Collection: db.Collection("user_roles"),
	}
	// Best practice: Initialize indexes at startup, but for now we can do it here or let main call it.
	// Since main calls NewMongoRepository, we'll let main call EnsureIndexes or do it here inside (async or sync).
	// To keep New simple, we won't blocking call it here, but we will impl the method.
	return repo
}

func (r *MongoRepository) EnsureIndexes(ctx context.Context) error {
	// 1. (user_id, user_type, scope, namespace, role) unique
	// Note: 'namespace' might be empty for some system roles if global System Admin?
	// But assuming the schema provided:
	idx1 := mongo.IndexModel{
		Keys: bson.D{
			{Key: "user_id", Value: 1},
			{Key: "user_type", Value: 1},
			{Key: "scope", Value: 1},
			{Key: "namespace", Value: 1}, // bson:"namespace"
			{Key: "role", Value: 1},
		},
		Options: options.Index().SetUnique(true).SetName("unique_user_assignment"),
	}

	// 2. (scope, namespace, role) where role="owner"
	// Partial index
	idx2 := mongo.IndexModel{
		Keys: bson.D{
			{Key: "scope", Value: 1},
			{Key: "namespace", Value: 1},
			{Key: "role", Value: 1},
		},
		Options: options.Index().
			SetUnique(true).
			SetName("unique_system_owner").
			SetPartialFilterExpression(bson.M{"role": model.RoleSystemOwner}),
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

func (r *MongoRepository) HasSystemRole(ctx context.Context, userID, role string) (bool, error) {
	// For performance, we add limit 1
	opts := options.Count().SetLimit(1)
	filter := bson.M{
		"user_id": userID,
		"scope":   model.ScopeSystem,
		"role":    role,
	}
	count, err := r.Collection.CountDocuments(ctx, filter, opts)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
