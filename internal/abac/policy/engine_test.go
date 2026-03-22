package policy

import (
	"testing"

	"rbac7/internal/abac/model"

	"github.com/stretchr/testify/assert"
)

func TestEvaluateCondition(t *testing.T) {
	// eq operator
	t.Run("eq string match", func(t *testing.T) {
		assert.True(t, EvaluateCondition("active", "eq", "active"))
	})
	t.Run("eq string no match", func(t *testing.T) {
		assert.False(t, EvaluateCondition("active", "eq", "inactive"))
	})

	// neq operator
	t.Run("neq string match", func(t *testing.T) {
		assert.True(t, EvaluateCondition("active", "neq", "inactive"))
	})
	t.Run("neq string no match", func(t *testing.T) {
		assert.False(t, EvaluateCondition("active", "neq", "active"))
	})

	// in operator
	t.Run("in match", func(t *testing.T) {
		assert.True(t, EvaluateCondition("editor", "in", []interface{}{"viewer", "editor", "admin"}))
	})
	t.Run("in no match", func(t *testing.T) {
		assert.False(t, EvaluateCondition("guest", "in", []interface{}{"viewer", "editor", "admin"}))
	})
	t.Run("in with string slice", func(t *testing.T) {
		assert.True(t, EvaluateCondition("editor", "in", []string{"viewer", "editor", "admin"}))
	})

	// not_in operator
	t.Run("not_in match", func(t *testing.T) {
		assert.True(t, EvaluateCondition("guest", "not_in", []interface{}{"viewer", "editor"}))
	})
	t.Run("not_in no match", func(t *testing.T) {
		assert.False(t, EvaluateCondition("editor", "not_in", []interface{}{"viewer", "editor"}))
	})

	// contains operator
	t.Run("contains match", func(t *testing.T) {
		assert.True(t, EvaluateCondition([]string{"group_a", "group_b"}, "contains", "group_a"))
	})
	t.Run("contains no match", func(t *testing.T) {
		assert.False(t, EvaluateCondition([]string{"group_a", "group_b"}, "contains", "group_c"))
	})

	// gt, gte, lt, lte operators
	t.Run("gt match", func(t *testing.T) {
		assert.True(t, EvaluateCondition(10, "gt", 5))
	})
	t.Run("gt no match", func(t *testing.T) {
		assert.False(t, EvaluateCondition(5, "gt", 10))
	})
	t.Run("gte match equal", func(t *testing.T) {
		assert.True(t, EvaluateCondition(10, "gte", 10))
	})
	t.Run("lt match", func(t *testing.T) {
		assert.True(t, EvaluateCondition(5, "lt", 10))
	})
	t.Run("lte match equal", func(t *testing.T) {
		assert.True(t, EvaluateCondition(10, "lte", 10))
	})

	// unknown operator
	t.Run("unknown operator", func(t *testing.T) {
		assert.False(t, EvaluateCondition("a", "unknown_op", "b"))
	})

	// nil field value
	t.Run("nil field eq", func(t *testing.T) {
		assert.False(t, EvaluateCondition(nil, "eq", "active"))
	})
}

func TestResolveSubjectField(t *testing.T) {
	subject := &model.Subject{
		UserID:           "user_1",
		Role:             "editor",
		Status:           "active",
		SensitivityLevel: "internal",
		GroupIDs:         []string{"group_a", "group_b"},
		CustomAttrs: []model.CustomAttr{
			{Key: "team", Value: "engineering"},
			{Key: "level", Value: 5},
		},
	}

	t.Run("resolve user_id", func(t *testing.T) {
		assert.Equal(t, "user_1", resolveSubjectField(subject, "user_id"))
	})
	t.Run("resolve role", func(t *testing.T) {
		assert.Equal(t, "editor", resolveSubjectField(subject, "role"))
	})
	t.Run("resolve status", func(t *testing.T) {
		assert.Equal(t, "active", resolveSubjectField(subject, "status"))
	})
	t.Run("resolve sensitivity_level", func(t *testing.T) {
		assert.Equal(t, "internal", resolveSubjectField(subject, "sensitivity_level"))
	})
	t.Run("resolve group_ids", func(t *testing.T) {
		assert.Equal(t, []string{"group_a", "group_b"}, resolveSubjectField(subject, "group_ids"))
	})
	t.Run("resolve custom attr", func(t *testing.T) {
		assert.Equal(t, "engineering", resolveSubjectField(subject, "custom.team"))
	})
	t.Run("resolve unknown custom attr", func(t *testing.T) {
		assert.Nil(t, resolveSubjectField(subject, "custom.unknown"))
	})
	t.Run("resolve unknown field", func(t *testing.T) {
		assert.Nil(t, resolveSubjectField(subject, "unknown_field"))
	})
}

func TestResolveResourceField(t *testing.T) {
	resource := &model.ResourceAttrs{
		ResourceID:       "doc_1",
		ResourceType:     "docs",
		ResourceParentID: "folder_1",
		OwnerID:          "user_100",
		SensitivityLevel: "restricted",
		Status:           "published",
		AllowedGroupIDs:  []string{"group_a"},
		DeniedGroupIDs:   []string{"group_c"},
		ResourceGroupIDs: []string{"group_x"},
		CustomAttrs: []model.CustomAttr{
			{Key: "doc.sensitivity", Value: "internal"},
		},
	}

	t.Run("resolve resource_id", func(t *testing.T) {
		assert.Equal(t, "doc_1", resolveResourceField(resource, "resource_id"))
	})
	t.Run("resolve resource_type", func(t *testing.T) {
		assert.Equal(t, "docs", resolveResourceField(resource, "resource_type"))
	})
	t.Run("resolve owner_id", func(t *testing.T) {
		assert.Equal(t, "user_100", resolveResourceField(resource, "owner_id"))
	})
	t.Run("resolve status", func(t *testing.T) {
		assert.Equal(t, "published", resolveResourceField(resource, "status"))
	})
	t.Run("resolve custom attr", func(t *testing.T) {
		assert.Equal(t, "internal", resolveResourceField(resource, "custom.doc.sensitivity"))
	})
	t.Run("resolve unknown field", func(t *testing.T) {
		assert.Nil(t, resolveResourceField(resource, "unknown"))
	})
}

func TestHasIntersection(t *testing.T) {
	t.Run("has intersection", func(t *testing.T) {
		assert.True(t, hasIntersection([]string{"a", "b", "c"}, []string{"b", "d"}))
	})
	t.Run("no intersection", func(t *testing.T) {
		assert.False(t, hasIntersection([]string{"a", "b"}, []string{"c", "d"}))
	})
	t.Run("empty slices", func(t *testing.T) {
		assert.False(t, hasIntersection([]string{}, []string{}))
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
