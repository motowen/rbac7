package repository

import (
	"context"
	"errors"
	"rbac7/internal/abac/model"
)

var (
	ErrDuplicate = errors.New("duplicate record")
	ErrNotFound  = errors.New("record not found")
)

// ABACRepository handles Subject CRUD operations (stored in DB)
type ABACRepository interface {
	// Subject CRUD
	CreateSubject(ctx context.Context, subject *model.Subject) error
	GetSubject(ctx context.Context, userID string) (*model.Subject, error)
	UpdateSubject(ctx context.Context, subject *model.Subject) error
	DeleteSubject(ctx context.Context, userID string, deletedBy string) error
	FindSubjects(ctx context.Context, filter model.SubjectFilter) ([]*model.Subject, error)

	// Group operations
	AddGroupToSubject(ctx context.Context, userID, groupID string) error
	RemoveGroupFromSubject(ctx context.Context, userID, groupID string) error

	// Org operations
	UpsertOrgMembership(ctx context.Context, userID string, org model.OrgMembership) error
	RemoveOrgMembership(ctx context.Context, userID, orgID string) error

	// Indexes
	EnsureIndexes(ctx context.Context) error
}

// PolicyRepository handles PolicyRule and AttributeDefinition CRUD operations
type PolicyRepository interface {
	// Policy Rules
	CreatePolicyRule(ctx context.Context, rule *model.PolicyRule) error
	GetPolicyRule(ctx context.Context, ruleID string) (*model.PolicyRule, error)
	UpdatePolicyRule(ctx context.Context, rule *model.PolicyRule) error
	DeletePolicyRule(ctx context.Context, ruleID string) error
	FindPolicyRules(ctx context.Context, resourceType, action string) ([]*model.PolicyRule, error)
	ListPolicyRules(ctx context.Context, filter model.PolicyRuleFilter) ([]*model.PolicyRule, error)

	// Attribute Definitions
	CreateAttributeDefinition(ctx context.Context, def *model.AttributeDefinition) error
	GetAttributeDefinition(ctx context.Context, key, scope string) (*model.AttributeDefinition, error)
	ListAttributeDefinitions(ctx context.Context, scope, resourceType string) ([]*model.AttributeDefinition, error)
	DeleteAttributeDefinition(ctx context.Context, key, scope string) error

	// Indexes
	EnsureIndexes(ctx context.Context) error
}
