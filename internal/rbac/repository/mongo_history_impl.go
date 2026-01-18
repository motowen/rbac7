package repository

import (
	"context"
	"rbac7/internal/rbac/model"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// MongoHistoryRepository implements HistoryRepository using MongoDB
type MongoHistoryRepository struct {
	Collection *mongo.Collection
}

// NewMongoHistoryRepository creates a new MongoHistoryRepository
func NewMongoHistoryRepository(db *mongo.Database, collectionName string) *MongoHistoryRepository {
	return &MongoHistoryRepository{
		Collection: db.Collection(collectionName),
	}
}

// EnsureHistoryIndexes creates indexes for efficient querying
func (r *MongoHistoryRepository) EnsureHistoryIndexes(ctx context.Context) error {
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

	_, err := r.Collection.Indexes().CreateMany(ctx, indexes)
	return err
}

// CreateHistory creates a new history record (append-only)
func (r *MongoHistoryRepository) CreateHistory(ctx context.Context, history *model.UserRoleHistory) error {
	if history.CreatedAt.IsZero() {
		history.CreatedAt = time.Now()
	}
	_, err := r.Collection.InsertOne(ctx, history)
	return err
}

// FindHistory finds history records with pagination and filtering
func (r *MongoHistoryRepository) FindHistory(ctx context.Context, req model.GetUserRoleHistoryReq) ([]*model.UserRoleHistory, int64, error) {
	filter := bson.M{"scope": req.Scope}

	// Add scope-specific filters
	if req.Scope == model.ScopeSystem {
		filter["namespace"] = req.Namespace
	} else if req.Scope == model.ScopeResource {
		// For resource scope, include main resource and child resources
		if len(req.ChildResourceIDs) > 0 {
			resourceIDs := append([]string{req.ResourceID}, req.ChildResourceIDs...)
			filter["resource_id"] = bson.M{"$in": resourceIDs}
		} else {
			filter["resource_id"] = req.ResourceID
		}
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
	total, err := r.Collection.CountDocuments(ctx, filter)
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

	cursor, err := r.Collection.Find(ctx, filter, findOptions)
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
