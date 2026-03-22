package policy

import (
	"context"
	"testing"

	"rbac7/internal/abac/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mockPolicyRepoForEngine is a minimal mock for Engine tests
type mockPolicyRepoForEngine struct {
	mock.Mock
}

func (m *mockPolicyRepoForEngine) CreatePolicyRule(ctx context.Context, rule *model.PolicyRule) error {
	return nil
}
func (m *mockPolicyRepoForEngine) GetPolicyRule(ctx context.Context, ruleID string) (*model.PolicyRule, error) {
	return nil, nil
}
func (m *mockPolicyRepoForEngine) UpdatePolicyRule(ctx context.Context, rule *model.PolicyRule) error {
	return nil
}
func (m *mockPolicyRepoForEngine) DeletePolicyRule(ctx context.Context, ruleID string) error {
	return nil
}
func (m *mockPolicyRepoForEngine) FindPolicyRules(ctx context.Context, resourceType, action string) ([]*model.PolicyRule, error) {
	args := m.Called(ctx, resourceType, action)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.PolicyRule), args.Error(1)
}
func (m *mockPolicyRepoForEngine) ListPolicyRules(ctx context.Context, filter model.PolicyRuleFilter) ([]*model.PolicyRule, error) {
	return nil, nil
}
func (m *mockPolicyRepoForEngine) CreateAttributeDefinition(ctx context.Context, def *model.AttributeDefinition) error {
	return nil
}
func (m *mockPolicyRepoForEngine) GetAttributeDefinition(ctx context.Context, key, scope string) (*model.AttributeDefinition, error) {
	return nil, nil
}
func (m *mockPolicyRepoForEngine) ListAttributeDefinitions(ctx context.Context, scope, resourceType string) ([]*model.AttributeDefinition, error) {
	return nil, nil
}
func (m *mockPolicyRepoForEngine) DeleteAttributeDefinition(ctx context.Context, key, scope string) error {
	return nil
}
func (m *mockPolicyRepoForEngine) EnsureIndexes(ctx context.Context) error {
	return nil
}

func newTestEngine(t *testing.T, mockRepo *mockPolicyRepoForEngine) *Engine {
	t.Helper()
	engine, err := NewEngine(mockRepo)
	require.NoError(t, err, "OPA Engine should initialize successfully")
	return engine
}

func TestOPAEngine_NewEngine(t *testing.T) {
	t.Run("initialize OPA engine successfully", func(t *testing.T) {
		mockRepo := new(mockPolicyRepoForEngine)
		engine, err := NewEngine(mockRepo)
		require.NoError(t, err)
		assert.NotNil(t, engine)
	})
}

func TestOPAEngine_GroupDeny(t *testing.T) {
	t.Run("deny when subject is in denied group", func(t *testing.T) {
		mockRepo := new(mockPolicyRepoForEngine)
		engine := newTestEngine(t, mockRepo)

		// FindPolicyRules won't be reached because group deny happens in Rego
		mockRepo.On("FindPolicyRules", mock.Anything, "docs", "read").Return([]*model.PolicyRule{}, nil)

		subject := &model.Subject{
			UserID:   "user_1",
			Role:     "editor",
			Status:   "active",
			GroupIDs: []string{"group_blocked"},
		}
		resource := &model.ResourceAttrs{
			ResourceID:     "doc_1",
			ResourceType:   "docs",
			DeniedGroupIDs: []string{"group_blocked", "group_other"},
		}

		resp, err := engine.CheckAccess(context.Background(), subject, resource, "read")
		require.NoError(t, err)
		assert.False(t, resp.Allowed)
		assert.Contains(t, resp.Reason, "denied group")
	})

	t.Run("allow when subject is NOT in denied group", func(t *testing.T) {
		mockRepo := new(mockPolicyRepoForEngine)
		engine := newTestEngine(t, mockRepo)

		mockRepo.On("FindPolicyRules", mock.Anything, "docs", "read").Return([]*model.PolicyRule{
			{
				Name: "allow active", ResourceType: "docs", Action: "read",
				Effect: "allow", Priority: 10, Enabled: true,
				Conditions: model.ConditionSet{
					Subject: []model.Condition{{Field: "status", Operator: "eq", Value: "active"}},
				},
			},
		}, nil)

		subject := &model.Subject{
			UserID: "user_1", Role: "editor", Status: "active", GroupIDs: []string{"group_safe"},
		}
		resource := &model.ResourceAttrs{
			ResourceID: "doc_1", ResourceType: "docs", DeniedGroupIDs: []string{"group_blocked"},
		}

		resp, err := engine.CheckAccess(context.Background(), subject, resource, "read")
		require.NoError(t, err)
		assert.True(t, resp.Allowed)
	})
}

func TestOPAEngine_GroupAllow(t *testing.T) {
	t.Run("deny when subject is not in allowed group", func(t *testing.T) {
		mockRepo := new(mockPolicyRepoForEngine)
		engine := newTestEngine(t, mockRepo)

		mockRepo.On("FindPolicyRules", mock.Anything, "docs", "read").Return([]*model.PolicyRule{}, nil)

		subject := &model.Subject{
			UserID: "user_1", Role: "editor", Status: "active", GroupIDs: []string{"group_x"},
		}
		resource := &model.ResourceAttrs{
			ResourceID: "doc_1", ResourceType: "docs",
			AllowedGroupIDs: []string{"group_a", "group_b"},
		}

		resp, err := engine.CheckAccess(context.Background(), subject, resource, "read")
		require.NoError(t, err)
		assert.False(t, resp.Allowed)
		assert.Contains(t, resp.Reason, "not in any allowed group")
	})

	t.Run("proceed when subject is in allowed group", func(t *testing.T) {
		mockRepo := new(mockPolicyRepoForEngine)
		engine := newTestEngine(t, mockRepo)

		mockRepo.On("FindPolicyRules", mock.Anything, "docs", "read").Return([]*model.PolicyRule{
			{
				Name: "allow readers", ResourceType: "docs", Action: "read",
				Effect: "allow", Priority: 10, Enabled: true,
				Conditions: model.ConditionSet{
					Subject: []model.Condition{{Field: "status", Operator: "eq", Value: "active"}},
				},
			},
		}, nil)

		subject := &model.Subject{
			UserID: "user_1", Role: "editor", Status: "active", GroupIDs: []string{"group_a"},
		}
		resource := &model.ResourceAttrs{
			ResourceID: "doc_1", ResourceType: "docs",
			AllowedGroupIDs: []string{"group_a", "group_b"},
		}

		resp, err := engine.CheckAccess(context.Background(), subject, resource, "read")
		require.NoError(t, err)
		assert.True(t, resp.Allowed)
	})
}

func TestOPAEngine_PolicyRules(t *testing.T) {
	t.Run("allow when matching allow rule", func(t *testing.T) {
		mockRepo := new(mockPolicyRepoForEngine)
		engine := newTestEngine(t, mockRepo)

		mockRepo.On("FindPolicyRules", mock.Anything, "docs", "read").Return([]*model.PolicyRule{
			{
				Name: "editors can read", ResourceType: "docs", Action: "read",
				Effect: "allow", Priority: 10, Enabled: true,
				Conditions: model.ConditionSet{
					Subject: []model.Condition{
						{Field: "status", Operator: "eq", Value: "active"},
						{Field: "role", Operator: "in", Value: []interface{}{"editor", "admin"}},
					},
				},
			},
		}, nil)

		subject := &model.Subject{
			UserID: "user_1", Role: "editor", Status: "active", GroupIDs: []string{},
		}
		resource := &model.ResourceAttrs{ResourceID: "doc_1", ResourceType: "docs"}

		resp, err := engine.CheckAccess(context.Background(), subject, resource, "read")
		require.NoError(t, err)
		assert.True(t, resp.Allowed)
		assert.Contains(t, resp.Reason, "editors can read")
	})

	t.Run("deny when no rules match", func(t *testing.T) {
		mockRepo := new(mockPolicyRepoForEngine)
		engine := newTestEngine(t, mockRepo)

		mockRepo.On("FindPolicyRules", mock.Anything, "docs", "read").Return([]*model.PolicyRule{
			{
				Name: "admins only", ResourceType: "docs", Action: "read",
				Effect: "allow", Priority: 10, Enabled: true,
				Conditions: model.ConditionSet{
					Subject: []model.Condition{{Field: "role", Operator: "eq", Value: "admin"}},
				},
			},
		}, nil)

		subject := &model.Subject{
			UserID: "user_1", Role: "viewer", Status: "active", GroupIDs: []string{},
		}
		resource := &model.ResourceAttrs{ResourceID: "doc_1", ResourceType: "docs"}

		resp, err := engine.CheckAccess(context.Background(), subject, resource, "read")
		require.NoError(t, err)
		assert.False(t, resp.Allowed)
	})

	t.Run("deny rule wins at same priority", func(t *testing.T) {
		mockRepo := new(mockPolicyRepoForEngine)
		engine := newTestEngine(t, mockRepo)

		mockRepo.On("FindPolicyRules", mock.Anything, "docs", "update").Return([]*model.PolicyRule{
			{
				Name: "editors can update", ResourceType: "docs", Action: "update",
				Effect: "allow", Priority: 10, Enabled: true,
				Conditions: model.ConditionSet{
					Subject: []model.Condition{{Field: "role", Operator: "eq", Value: "editor"}},
				},
			},
			{
				Name: "deny restricted", ResourceType: "docs", Action: "update",
				Effect: "deny", Priority: 10, Enabled: true,
				Conditions: model.ConditionSet{
					Subject: []model.Condition{{Field: "sensitivity_level", Operator: "eq", Value: "restricted"}},
				},
			},
		}, nil)

		subject := &model.Subject{
			UserID: "user_1", Role: "editor", Status: "active",
			SensitivityLevel: "restricted", GroupIDs: []string{},
		}
		resource := &model.ResourceAttrs{ResourceID: "doc_1", ResourceType: "docs"}

		resp, err := engine.CheckAccess(context.Background(), subject, resource, "update")
		require.NoError(t, err)
		assert.False(t, resp.Allowed)
		assert.Contains(t, resp.Reason, "denied by rule")
	})

	t.Run("no rules returns default deny", func(t *testing.T) {
		mockRepo := new(mockPolicyRepoForEngine)
		engine := newTestEngine(t, mockRepo)

		mockRepo.On("FindPolicyRules", mock.Anything, "docs", "delete").Return([]*model.PolicyRule{}, nil)

		subject := &model.Subject{
			UserID: "user_1", Role: "editor", Status: "active", GroupIDs: []string{},
		}
		resource := &model.ResourceAttrs{ResourceID: "doc_1", ResourceType: "docs"}

		resp, err := engine.CheckAccess(context.Background(), subject, resource, "delete")
		require.NoError(t, err)
		assert.False(t, resp.Allowed)
		assert.Contains(t, resp.Reason, "no matching policy rules")
	})

	t.Run("resource condition check", func(t *testing.T) {
		mockRepo := new(mockPolicyRepoForEngine)
		engine := newTestEngine(t, mockRepo)

		mockRepo.On("FindPolicyRules", mock.Anything, "docs", "delete").Return([]*model.PolicyRule{
			{
				Name: "delete only drafts", ResourceType: "docs", Action: "delete",
				Effect: "allow", Priority: 10, Enabled: true,
				Conditions: model.ConditionSet{
					Subject:  []model.Condition{{Field: "role", Operator: "eq", Value: "admin"}},
					Resource: []model.Condition{{Field: "status", Operator: "eq", Value: "draft"}},
				},
			},
		}, nil)

		subject := &model.Subject{
			UserID: "user_1", Role: "admin", Status: "active", GroupIDs: []string{},
		}
		resource := &model.ResourceAttrs{ResourceID: "doc_1", ResourceType: "docs", Status: "draft"}

		resp, err := engine.CheckAccess(context.Background(), subject, resource, "delete")
		require.NoError(t, err)
		assert.True(t, resp.Allowed)
	})

	t.Run("custom attribute condition", func(t *testing.T) {
		mockRepo := new(mockPolicyRepoForEngine)
		engine := newTestEngine(t, mockRepo)

		mockRepo.On("FindPolicyRules", mock.Anything, "docs", "read").Return([]*model.PolicyRule{
			{
				Name: "engineering team access", ResourceType: "docs", Action: "read",
				Effect: "allow", Priority: 10, Enabled: true,
				Conditions: model.ConditionSet{
					Subject: []model.Condition{{Field: "custom.team", Operator: "eq", Value: "engineering"}},
				},
			},
		}, nil)

		subject := &model.Subject{
			UserID: "user_1", Role: "editor", Status: "active", GroupIDs: []string{},
			CustomAttrs: []model.CustomAttr{{Key: "team", Value: "engineering"}},
		}
		resource := &model.ResourceAttrs{ResourceID: "doc_1", ResourceType: "docs"}

		resp, err := engine.CheckAccess(context.Background(), subject, resource, "read")
		require.NoError(t, err)
		assert.True(t, resp.Allowed)
		assert.Contains(t, resp.Reason, "engineering team access")
	})
}

func TestSortRulesByPriority(t *testing.T) {
	rules := []*model.PolicyRule{
		{Name: "low", Priority: 1},
		{Name: "high", Priority: 10},
		{Name: "mid", Priority: 5},
	}
	SortRulesByPriority(rules)
	assert.Equal(t, "high", rules[0].Name)
	assert.Equal(t, "mid", rules[1].Name)
	assert.Equal(t, "low", rules[2].Name)
}
