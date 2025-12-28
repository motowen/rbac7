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

func (r *MongoRepository) CountSystemOwners(ctx context.Context, namespace string) (int64, error) {
	filter := bson.M{
		"scope":      model.ScopeSystem,
		"namespace":  namespace,
		"role":       model.RoleSystemOwner,
		"deleted_at": nil,
	}
	return r.SystemRoles.CountDocuments(ctx, filter)
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
