package repository

import (
	"context"
	"time"

	"system/internal/system/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type SystemRepository interface {
	CreateSystem(ctx context.Context, system *model.System) error
	UpdateSystem(ctx context.Context, namespace string, name, description *string) (*model.System, error)
	GetSystemByNamespace(ctx context.Context, namespace string) (*model.System, error)
	GetSystemsByNamespaces(ctx context.Context, namespaces []string) ([]*model.System, error)
}

type MongoSystemRepository struct {
	collection *mongo.Collection
}

func NewMongoSystemRepository(db *mongo.Database) *MongoSystemRepository {
	return &MongoSystemRepository{
		collection: db.Collection("system"),
	}
}

func (r *MongoSystemRepository) CreateSystem(ctx context.Context, system *model.System) error {
	system.CreatedAt = time.Now()
	system.UpdatedAt = time.Now()
	_, err := r.collection.InsertOne(ctx, system)
	return err
}

func (r *MongoSystemRepository) UpdateSystem(ctx context.Context, namespace string, name, description *string) (*model.System, error) {
	update := bson.M{"$set": bson.M{"updated_at": time.Now()}}

	if name != nil {
		update["$set"].(bson.M)["name"] = *name
	}
	if description != nil {
		update["$set"].(bson.M)["description"] = *description
	}

	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var result model.System
	err := r.collection.FindOneAndUpdate(ctx, bson.M{"namespace": namespace}, update, opts).Decode(&result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (r *MongoSystemRepository) GetSystemByNamespace(ctx context.Context, namespace string) (*model.System, error) {
	var result model.System
	err := r.collection.FindOne(ctx, bson.M{"namespace": namespace}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return &result, nil
}

func (r *MongoSystemRepository) GetSystemsByNamespaces(ctx context.Context, namespaces []string) ([]*model.System, error) {
	if len(namespaces) == 0 {
		return []*model.System{}, nil
	}

	cursor, err := r.collection.Find(ctx, bson.M{"namespace": bson.M{"$in": namespaces}})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []*model.System
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}
	return results, nil
}
