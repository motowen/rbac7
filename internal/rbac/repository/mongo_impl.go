package repository

import (
	"context"
	"rbac7/internal/rbac/model"

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
