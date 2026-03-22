package abac

import (
	"context"
	"rbac7/internal/abac/model"

	"github.com/stretchr/testify/mock"
)

// MockABACRepository is a mock implementation of repository.ABACRepository
type MockABACRepository struct {
	mock.Mock
}

func (m *MockABACRepository) CreateSubject(ctx context.Context, subject *model.Subject) error {
	args := m.Called(ctx, subject)
	return args.Error(0)
}

func (m *MockABACRepository) GetSubject(ctx context.Context, userID string) (*model.Subject, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Subject), args.Error(1)
}

func (m *MockABACRepository) UpdateSubject(ctx context.Context, subject *model.Subject) error {
	args := m.Called(ctx, subject)
	return args.Error(0)
}

func (m *MockABACRepository) DeleteSubject(ctx context.Context, userID string, deletedBy string) error {
	args := m.Called(ctx, userID, deletedBy)
	return args.Error(0)
}

func (m *MockABACRepository) FindSubjects(ctx context.Context, filter model.SubjectFilter) ([]*model.Subject, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.Subject), args.Error(1)
}

func (m *MockABACRepository) AddGroupToSubject(ctx context.Context, userID, groupID string) error {
	args := m.Called(ctx, userID, groupID)
	return args.Error(0)
}

func (m *MockABACRepository) RemoveGroupFromSubject(ctx context.Context, userID, groupID string) error {
	args := m.Called(ctx, userID, groupID)
	return args.Error(0)
}

func (m *MockABACRepository) UpsertOrgMembership(ctx context.Context, userID string, org model.OrgMembership) error {
	args := m.Called(ctx, userID, org)
	return args.Error(0)
}

func (m *MockABACRepository) RemoveOrgMembership(ctx context.Context, userID, orgID string) error {
	args := m.Called(ctx, userID, orgID)
	return args.Error(0)
}

func (m *MockABACRepository) EnsureIndexes(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// MockPolicyRepository is a mock implementation of repository.PolicyRepository
type MockPolicyRepository struct {
	mock.Mock
}

func (m *MockPolicyRepository) CreatePolicyRule(ctx context.Context, rule *model.PolicyRule) error {
	args := m.Called(ctx, rule)
	return args.Error(0)
}

func (m *MockPolicyRepository) GetPolicyRule(ctx context.Context, ruleID string) (*model.PolicyRule, error) {
	args := m.Called(ctx, ruleID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.PolicyRule), args.Error(1)
}

func (m *MockPolicyRepository) UpdatePolicyRule(ctx context.Context, rule *model.PolicyRule) error {
	args := m.Called(ctx, rule)
	return args.Error(0)
}

func (m *MockPolicyRepository) DeletePolicyRule(ctx context.Context, ruleID string) error {
	args := m.Called(ctx, ruleID)
	return args.Error(0)
}

func (m *MockPolicyRepository) FindPolicyRules(ctx context.Context, resourceType, action string) ([]*model.PolicyRule, error) {
	args := m.Called(ctx, resourceType, action)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.PolicyRule), args.Error(1)
}

func (m *MockPolicyRepository) ListPolicyRules(ctx context.Context, filter model.PolicyRuleFilter) ([]*model.PolicyRule, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.PolicyRule), args.Error(1)
}

func (m *MockPolicyRepository) CreateAttributeDefinition(ctx context.Context, def *model.AttributeDefinition) error {
	args := m.Called(ctx, def)
	return args.Error(0)
}

func (m *MockPolicyRepository) GetAttributeDefinition(ctx context.Context, key, scope string) (*model.AttributeDefinition, error) {
	args := m.Called(ctx, key, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.AttributeDefinition), args.Error(1)
}

func (m *MockPolicyRepository) ListAttributeDefinitions(ctx context.Context, scope, resourceType string) ([]*model.AttributeDefinition, error) {
	args := m.Called(ctx, scope, resourceType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.AttributeDefinition), args.Error(1)
}

func (m *MockPolicyRepository) DeleteAttributeDefinition(ctx context.Context, key, scope string) error {
	args := m.Called(ctx, key, scope)
	return args.Error(0)
}

func (m *MockPolicyRepository) EnsureIndexes(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}
