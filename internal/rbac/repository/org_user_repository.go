package repository

import (
	"context"
	"rbac7/internal/rbac/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// OrgUser holds organizational attributes for a user, stored in a separate collection.
// This data is imported periodically from an external system.
type OrgUser struct {
	UserID      string `bson:"user_id"`
	FunctionID  string `bson:"function_id"`
	FunctionID1 string `bson:"function_id1,omitempty"` // optional
	DivisionID  string `bson:"division_id"`
	DeptID      string `bson:"dept_id"`
	SectID      string `bson:"sect_id"`
}

// OrgIDs returns all non-empty org IDs (used to query org roles)
func (o *OrgUser) OrgIDs() []string {
	ids := make([]string, 0, 5)
	if o.FunctionID != "" {
		ids = append(ids, o.FunctionID)
	}
	if o.FunctionID1 != "" {
		ids = append(ids, o.FunctionID1)
	}
	if o.DivisionID != "" {
		ids = append(ids, o.DivisionID)
	}
	if o.DeptID != "" {
		ids = append(ids, o.DeptID)
	}
	if o.SectID != "" {
		ids = append(ids, o.SectID)
	}
	return ids
}

// OrgUserRepository provides org data lookup for permission checks.
// Data is stored in the same MongoDB, in a separate collection.
type OrgUserRepository interface {
	// GetOrgUser returns the org user data for the given userID.
	// Returns nil (no error) if not found, meaning the user has no org affiliation.
	GetOrgUser(ctx context.Context, userID string) (*OrgUser, error)
}

// MongoOrgUserRepository implements OrgUserRepository using MongoDB
type MongoOrgUserRepository struct {
	Collection *mongo.Collection
}

// NewMongoOrgUserRepository creates a new MongoOrgUserRepository
func NewMongoOrgUserRepository(db *mongo.Database, collectionName string) *MongoOrgUserRepository {
	return &MongoOrgUserRepository{
		Collection: db.Collection(collectionName),
	}
}

// GetOrgUser fetches org user data by userID. Returns nil if not found.
func (r *MongoOrgUserRepository) GetOrgUser(ctx context.Context, userID string) (*OrgUser, error) {
	var orgUser OrgUser
	err := r.Collection.FindOne(ctx, bson.M{"user_id": userID}).Decode(&orgUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil // Not found = no org affiliation
		}
		return nil, err
	}
	return &orgUser, nil
}

// FindUserRolesByUserIDs finds roles where user_id IN userIDs and user_type = userType.
// Used for org permission check: find all org roles matching a user's org attribute IDs.
func (r *MongoRepository) FindUserRolesByUserIDs(ctx context.Context, userIDs []string, userType, scope, namespace, resourceID, resourceType string) ([]*model.UserRole, error) {
	if len(userIDs) == 0 {
		return nil, nil
	}

	query := bson.M{
		"user_id":    bson.M{"$in": userIDs},
		"user_type":  userType,
		"scope":      scope,
		"deleted_at": nil,
	}

	if scope == model.ScopeSystem && namespace != "" {
		query["namespace"] = namespace
	}
	if scope == model.ScopeResource {
		if resourceID != "" {
			query["resource_id"] = resourceID
		}
		if resourceType != "" {
			query["resource_type"] = resourceType
		}
	}

	var coll *mongo.Collection
	if scope == model.ScopeSystem {
		coll = r.SystemRoles
	} else {
		coll = r.ResourceRoles
	}

	cursor, err := coll.Find(ctx, query)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var roles []*model.UserRole
	if err := cursor.All(ctx, &roles); err != nil {
		return nil, err
	}
	return roles, nil
}
