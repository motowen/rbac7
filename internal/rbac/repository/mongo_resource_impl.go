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
func (r *MongoRepository) CountResourceRoles(ctx context.Context, resourceID, resourceType string) (int64, error) {
	filter := bson.M{
		"resource_id":   resourceID,
		"resource_type": resourceType,
		"scope":         model.ScopeResource,
		"deleted_at":    nil,
	}
	return r.ResourceRoles.CountDocuments(ctx, filter)
}
