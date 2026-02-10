package repository

import (
	"context"
	"errors"
	"time"

	"system/internal/system/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	ErrLocked      = errors.New("entity is locked by another user")
	ErrLockNotHeld = errors.New("lock not held by this user")
)

// LockRepository defines the interface for entity lock operations
type LockRepository interface {
	Lock(ctx context.Context, entityType, entityID, userID string, duration time.Duration) (*model.EntityLock, error)
	Unlock(ctx context.Context, entityType, entityID, userID string) error
	GetLock(ctx context.Context, entityType, entityID string) (*model.EntityLock, error)
	IsLockedByOther(ctx context.Context, entityType, entityID, userID string) (bool, error)
	EnsureIndexes(ctx context.Context) error
}

// MongoLockRepository implements LockRepository using a shared entity_locks collection
type MongoLockRepository struct {
	collection *mongo.Collection
}

// NewMongoLockRepository creates a new MongoLockRepository
func NewMongoLockRepository(db *mongo.Database) *MongoLockRepository {
	return &MongoLockRepository{
		collection: db.Collection("entity_locks"),
	}
}

func (r *MongoLockRepository) Lock(ctx context.Context, entityType, entityID, userID string, duration time.Duration) (*model.EntityLock, error) {
	now := time.Now()
	expiresAt := now.Add(duration)

	// Try to acquire lock - either no lock exists, lock expired, or already owned by this user
	filter := bson.M{
		"entity_type": entityType,
		"entity_id":   entityID,
		"$or": []bson.M{
			{"expires_at": bson.M{"$lt": now}},
			{"locked_by": userID},
		},
	}

	lock := &model.EntityLock{
		EntityType: entityType,
		EntityID:   entityID,
		LockedBy:   userID,
		LockedAt:   now,
		ExpiresAt:  expiresAt,
	}

	opts := options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)
	var result model.EntityLock
	err := r.collection.FindOneAndUpdate(
		ctx,
		filter,
		bson.M{"$set": lock},
		opts,
	).Decode(&result)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, ErrLocked
		}
		return nil, err
	}

	return &result, nil
}

func (r *MongoLockRepository) Unlock(ctx context.Context, entityType, entityID, userID string) error {
	result, err := r.collection.DeleteOne(ctx, bson.M{
		"entity_type": entityType,
		"entity_id":   entityID,
		"locked_by":   userID,
	})
	if err != nil {
		return err
	}
	if result.DeletedCount == 0 {
		return ErrLockNotHeld
	}
	return nil
}

func (r *MongoLockRepository) GetLock(ctx context.Context, entityType, entityID string) (*model.EntityLock, error) {
	var result model.EntityLock
	err := r.collection.FindOne(ctx, bson.M{
		"entity_type": entityType,
		"entity_id":   entityID,
		"expires_at":  bson.M{"$gt": time.Now()},
	}).Decode(&result)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return &result, nil
}

func (r *MongoLockRepository) IsLockedByOther(ctx context.Context, entityType, entityID, userID string) (bool, error) {
	lock, err := r.GetLock(ctx, entityType, entityID)
	if err != nil {
		return false, err
	}
	if lock == nil {
		return false, nil
	}
	return lock.LockedBy != userID, nil
}

func (r *MongoLockRepository) EnsureIndexes(ctx context.Context) error {
	indexes := []mongo.IndexModel{
		// Unique index on entity_type + entity_id (one lock per entity)
		{
			Keys: bson.D{
				{Key: "entity_type", Value: 1},
				{Key: "entity_id", Value: 1},
			},
			Options: options.Index().SetUnique(true).SetName("uniq_entity_lock"),
		},
		// Index on expires_at for lock expiration queries
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetName("idx_expires_at"),
		},
	}

	_, err := r.collection.Indexes().CreateMany(ctx, indexes)
	return err
}
