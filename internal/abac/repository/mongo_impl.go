package repository

import (
	"context"
	"rbac7/internal/abac/model"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// MongoABACRepository implements ABACRepository using MongoDB
type MongoABACRepository struct {
	Subjects *mongo.Collection
}

// NewMongoABACRepository creates a new MongoABACRepository
func NewMongoABACRepository(db *mongo.Database, subjectsCollection string) *MongoABACRepository {
	return &MongoABACRepository{
		Subjects: db.Collection(subjectsCollection),
	}
}

// EnsureIndexes creates necessary indexes for the subjects collection
func (r *MongoABACRepository) EnsureIndexes(ctx context.Context) error {
	indexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "user_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{{Key: "group_ids", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "orgs.org_id", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "role", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "status", Value: 1}},
		},
	}
	_, err := r.Subjects.Indexes().CreateMany(ctx, indexes)
	return err
}

// CreateSubject creates a new subject
func (r *MongoABACRepository) CreateSubject(ctx context.Context, subject *model.Subject) error {
	subject.CreatedAt = time.Now()
	subject.UpdatedAt = time.Now()

	_, err := r.Subjects.InsertOne(ctx, subject)
	if mongo.IsDuplicateKeyError(err) {
		return ErrDuplicate
	}
	return err
}

// GetSubject retrieves a subject by user_id
func (r *MongoABACRepository) GetSubject(ctx context.Context, userID string) (*model.Subject, error) {
	var subject model.Subject
	err := r.Subjects.FindOne(ctx, bson.M{
		"user_id":    userID,
		"deleted_at": nil,
	}).Decode(&subject)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return &subject, nil
}

// UpdateSubject updates an existing subject
func (r *MongoABACRepository) UpdateSubject(ctx context.Context, subject *model.Subject) error {
	subject.UpdatedAt = time.Now()

	filter := bson.M{
		"user_id":    subject.UserID,
		"deleted_at": nil,
	}

	update := bson.M{
		"$set": bson.M{
			"role":              subject.Role,
			"status":            subject.Status,
			"sensitivity_level": subject.SensitivityLevel,
			"orgs":              subject.Orgs,
			"group_ids":         subject.GroupIDs,
			"custom_attrs":      subject.CustomAttrs,
			"updated_at":        subject.UpdatedAt,
			"updated_by":        subject.UpdatedBy,
		},
	}

	result, err := r.Subjects.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteSubject soft-deletes a subject
func (r *MongoABACRepository) DeleteSubject(ctx context.Context, userID string, deletedBy string) error {
	now := time.Now()
	filter := bson.M{
		"user_id":    userID,
		"deleted_at": nil,
	}
	update := bson.M{
		"$set": bson.M{
			"deleted_at": now,
			"updated_at": now,
			"updated_by": deletedBy,
		},
	}

	result, err := r.Subjects.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return ErrNotFound
	}
	return nil
}

// FindSubjects queries subjects with a filter
func (r *MongoABACRepository) FindSubjects(ctx context.Context, filter model.SubjectFilter) ([]*model.Subject, error) {
	query := bson.M{"deleted_at": nil}
	if filter.UserID != "" {
		query["user_id"] = filter.UserID
	}
	if filter.Role != "" {
		query["role"] = filter.Role
	}
	if filter.Status != "" {
		query["status"] = filter.Status
	}
	if filter.GroupID != "" {
		query["group_ids"] = filter.GroupID
	}

	cursor, err := r.Subjects.Find(ctx, query)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var subjects []*model.Subject
	if err := cursor.All(ctx, &subjects); err != nil {
		return nil, err
	}
	return subjects, nil
}

// AddGroupToSubject adds a group_id to the subject's group_ids array
func (r *MongoABACRepository) AddGroupToSubject(ctx context.Context, userID, groupID string) error {
	filter := bson.M{
		"user_id":    userID,
		"deleted_at": nil,
	}
	update := bson.M{
		"$addToSet": bson.M{"group_ids": groupID},
		"$set":      bson.M{"updated_at": time.Now()},
	}

	result, err := r.Subjects.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return ErrNotFound
	}
	return nil
}

// RemoveGroupFromSubject removes a group_id from the subject's group_ids array
func (r *MongoABACRepository) RemoveGroupFromSubject(ctx context.Context, userID, groupID string) error {
	filter := bson.M{
		"user_id":    userID,
		"deleted_at": nil,
	}
	update := bson.M{
		"$pull": bson.M{"group_ids": groupID},
		"$set":  bson.M{"updated_at": time.Now()},
	}

	result, err := r.Subjects.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return ErrNotFound
	}
	return nil
}

// UpsertOrgMembership adds or updates an org membership for a subject
func (r *MongoABACRepository) UpsertOrgMembership(ctx context.Context, userID string, org model.OrgMembership) error {
	// First try to update existing org membership
	filter := bson.M{
		"user_id":      userID,
		"deleted_at":   nil,
		"orgs.org_id":  org.OrgID,
	}
	update := bson.M{
		"$set": bson.M{
			"orgs.$.org_type": org.OrgType,
			"updated_at":      time.Now(),
		},
	}

	result, err := r.Subjects.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}

	if result.MatchedCount > 0 {
		return nil // Updated existing
	}

	// No existing org found, add new one
	filter = bson.M{
		"user_id":    userID,
		"deleted_at": nil,
	}
	update = bson.M{
		"$push": bson.M{"orgs": org},
		"$set":  bson.M{"updated_at": time.Now()},
	}

	result, err = r.Subjects.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return ErrNotFound
	}
	return nil
}

// RemoveOrgMembership removes an org membership from a subject
func (r *MongoABACRepository) RemoveOrgMembership(ctx context.Context, userID, orgID string) error {
	filter := bson.M{
		"user_id":    userID,
		"deleted_at": nil,
	}
	update := bson.M{
		"$pull": bson.M{"orgs": bson.M{"org_id": orgID}},
		"$set":  bson.M{"updated_at": time.Now()},
	}

	result, err := r.Subjects.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return ErrNotFound
	}
	return nil
}

// --- MongoPolicyRepository ---

// MongoPolicyRepository implements PolicyRepository using MongoDB
type MongoPolicyRepository struct {
	PolicyRules    *mongo.Collection
	AttributeDefs  *mongo.Collection
}

// NewMongoPolicyRepository creates a new MongoPolicyRepository
func NewMongoPolicyRepository(db *mongo.Database, policyRulesCollection, attributeDefsCollection string) *MongoPolicyRepository {
	return &MongoPolicyRepository{
		PolicyRules:   db.Collection(policyRulesCollection),
		AttributeDefs: db.Collection(attributeDefsCollection),
	}
}

// EnsureIndexes creates necessary indexes for policy collections
func (r *MongoPolicyRepository) EnsureIndexes(ctx context.Context) error {
	policyIndexes := []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: "resource_type", Value: 1},
				{Key: "action", Value: 1},
				{Key: "enabled", Value: 1},
			},
		},
		{
			Keys: bson.D{{Key: "priority", Value: -1}},
		},
	}
	if _, err := r.PolicyRules.Indexes().CreateMany(ctx, policyIndexes); err != nil {
		return err
	}

	attrIndexes := []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: "key", Value: 1},
				{Key: "scope", Value: 1},
			},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{
				{Key: "scope", Value: 1},
				{Key: "resource_type", Value: 1},
			},
		},
	}
	_, err := r.AttributeDefs.Indexes().CreateMany(ctx, attrIndexes)
	return err
}

// --- Policy Rule CRUD ---

// CreatePolicyRule creates a new policy rule
func (r *MongoPolicyRepository) CreatePolicyRule(ctx context.Context, rule *model.PolicyRule) error {
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()

	result, err := r.PolicyRules.InsertOne(ctx, rule)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return ErrDuplicate
		}
		return err
	}
	// Set the generated ID back
	if oid, ok := result.InsertedID.(primitive.ObjectID); ok {
		rule.ID = oid.Hex()
	}
	return nil
}

// GetPolicyRule retrieves a policy rule by ID
func (r *MongoPolicyRepository) GetPolicyRule(ctx context.Context, ruleID string) (*model.PolicyRule, error) {
	oid, err := primitive.ObjectIDFromHex(ruleID)
	if err != nil {
		return nil, ErrNotFound
	}

	var rule model.PolicyRule
	err = r.PolicyRules.FindOne(ctx, bson.M{
		"_id":        oid,
		"deleted_at": nil,
	}).Decode(&rule)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return &rule, nil
}

// UpdatePolicyRule updates an existing policy rule
func (r *MongoPolicyRepository) UpdatePolicyRule(ctx context.Context, rule *model.PolicyRule) error {
	oid, err := primitive.ObjectIDFromHex(rule.ID)
	if err != nil {
		return ErrNotFound
	}

	rule.UpdatedAt = time.Now()

	filter := bson.M{
		"_id":        oid,
		"deleted_at": nil,
	}
	update := bson.M{
		"$set": bson.M{
			"name":          rule.Name,
			"description":   rule.Description,
			"resource_type": rule.ResourceType,
			"action":        rule.Action,
			"effect":        rule.Effect,
			"priority":      rule.Priority,
			"conditions":    rule.Conditions,
			"enabled":       rule.Enabled,
			"updated_at":    rule.UpdatedAt,
			"updated_by":    rule.UpdatedBy,
		},
	}

	result, err := r.PolicyRules.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return ErrNotFound
	}
	return nil
}

// DeletePolicyRule soft-deletes a policy rule
func (r *MongoPolicyRepository) DeletePolicyRule(ctx context.Context, ruleID string) error {
	oid, err := primitive.ObjectIDFromHex(ruleID)
	if err != nil {
		return ErrNotFound
	}

	now := time.Now()
	filter := bson.M{
		"_id":        oid,
		"deleted_at": nil,
	}
	update := bson.M{
		"$set": bson.M{
			"deleted_at": now,
			"updated_at": now,
		},
	}

	result, err := r.PolicyRules.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return ErrNotFound
	}
	return nil
}

// FindPolicyRules finds enabled policy rules for a given resource type and action
func (r *MongoPolicyRepository) FindPolicyRules(ctx context.Context, resourceType, action string) ([]*model.PolicyRule, error) {
	query := bson.M{
		"resource_type": resourceType,
		"action":        action,
		"enabled":       true,
		"deleted_at":    nil,
	}
	opts := options.Find().SetSort(bson.D{{Key: "priority", Value: -1}})

	cursor, err := r.PolicyRules.Find(ctx, query, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var rules []*model.PolicyRule
	if err := cursor.All(ctx, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// ListPolicyRules lists policy rules with optional filtering
func (r *MongoPolicyRepository) ListPolicyRules(ctx context.Context, filter model.PolicyRuleFilter) ([]*model.PolicyRule, error) {
	query := bson.M{"deleted_at": nil}
	if filter.ResourceType != "" {
		query["resource_type"] = filter.ResourceType
	}
	if filter.Action != "" {
		query["action"] = filter.Action
	}
	if filter.Enabled != nil {
		query["enabled"] = *filter.Enabled
	}
	opts := options.Find().SetSort(bson.D{{Key: "priority", Value: -1}})

	cursor, err := r.PolicyRules.Find(ctx, query, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var rules []*model.PolicyRule
	if err := cursor.All(ctx, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// --- Attribute Definition CRUD ---

// CreateAttributeDefinition creates a new attribute definition
func (r *MongoPolicyRepository) CreateAttributeDefinition(ctx context.Context, def *model.AttributeDefinition) error {
	def.CreatedAt = time.Now()
	def.UpdatedAt = time.Now()

	_, err := r.PolicyRules.Database().Collection(r.AttributeDefs.Name()).InsertOne(ctx, def)
	if mongo.IsDuplicateKeyError(err) {
		return ErrDuplicate
	}
	return err
}

// GetAttributeDefinition retrieves an attribute definition by key and scope
func (r *MongoPolicyRepository) GetAttributeDefinition(ctx context.Context, key, scope string) (*model.AttributeDefinition, error) {
	var def model.AttributeDefinition
	err := r.AttributeDefs.FindOne(ctx, bson.M{
		"key":   key,
		"scope": scope,
	}).Decode(&def)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}
	return &def, nil
}

// ListAttributeDefinitions lists attribute definitions with optional filtering
func (r *MongoPolicyRepository) ListAttributeDefinitions(ctx context.Context, scope, resourceType string) ([]*model.AttributeDefinition, error) {
	query := bson.M{}
	if scope != "" {
		query["scope"] = scope
	}
	if resourceType != "" {
		query["resource_type"] = resourceType
	}

	cursor, err := r.AttributeDefs.Find(ctx, query)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var defs []*model.AttributeDefinition
	if err := cursor.All(ctx, &defs); err != nil {
		return nil, err
	}
	return defs, nil
}

// DeleteAttributeDefinition deletes an attribute definition by key and scope
func (r *MongoPolicyRepository) DeleteAttributeDefinition(ctx context.Context, key, scope string) error {
	result, err := r.AttributeDefs.DeleteOne(ctx, bson.M{
		"key":   key,
		"scope": scope,
	})
	if err != nil {
		return err
	}
	if result.DeletedCount == 0 {
		return ErrNotFound
	}
	return nil
}
