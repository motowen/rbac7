package abac

import (
	"net/http"
	"testing"

	"rbac7/internal/abac/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestPostCheckAccess(t *testing.T) {
	apiPath := "/api/v1/access/check"

	t.Run("allow when policy rule matches and effect is allow", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("GetSubject", mock.Anything, "user_1").Return(&model.Subject{
			UserID:   "user_1",
			Role:     "editor",
			Status:   "active",
			GroupIDs: []string{"group_a"},
		}, nil)

		mockPolicyRepo.On("FindPolicyRules", mock.Anything, "docs", "read").Return([]*model.PolicyRule{
			{
				Name:         "editors can read docs",
				ResourceType: "docs",
				Action:       "read",
				Effect:       model.EffectAllow,
				Priority:     10,
				Conditions: model.ConditionSet{
					Subject: []model.Condition{
						{Field: "status", Operator: "eq", Value: "active"},
						{Field: "role", Operator: "in", Value: []interface{}{"editor", "admin", "owner"}},
					},
				},
				Enabled: true,
			},
		}, nil)

		payload := map[string]interface{}{
			"subject_id": "user_1",
			"action":     "read",
			"resource": map[string]interface{}{
				"resource_id":   "doc_1",
				"resource_type": "docs",
			},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":true`)
	})

	t.Run("deny when subject is in denied group", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("GetSubject", mock.Anything, "user_1").Return(&model.Subject{
			UserID:   "user_1",
			Role:     "editor",
			Status:   "active",
			GroupIDs: []string{"group_blocked"},
		}, nil)

		mockPolicyRepo.On("FindPolicyRules", mock.Anything, "docs", "read").Return([]*model.PolicyRule{}, nil)

		payload := map[string]interface{}{
			"subject_id": "user_1",
			"action":     "read",
			"resource": map[string]interface{}{
				"resource_id":      "doc_1",
				"resource_type":    "docs",
				"denied_group_ids": []string{"group_blocked"},
			},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":false`)
		assert.Contains(t, rec.Body.String(), `denied group`)
	})

	t.Run("deny when subject is not in allowed group", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("GetSubject", mock.Anything, "user_1").Return(&model.Subject{
			UserID:   "user_1",
			Role:     "editor",
			Status:   "active",
			GroupIDs: []string{"group_x"},
		}, nil)

		mockPolicyRepo.On("FindPolicyRules", mock.Anything, "docs", "read").Return([]*model.PolicyRule{}, nil)

		payload := map[string]interface{}{
			"subject_id": "user_1",
			"action":     "read",
			"resource": map[string]interface{}{
				"resource_id":       "doc_1",
				"resource_type":     "docs",
				"allowed_group_ids": []string{"group_a", "group_b"},
			},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":false`)
		assert.Contains(t, rec.Body.String(), `not in any allowed group`)
	})

	t.Run("deny when no matching policy rules", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("GetSubject", mock.Anything, "user_1").Return(&model.Subject{
			UserID:   "user_1",
			Role:     "viewer",
			Status:   "active",
			GroupIDs: []string{},
		}, nil)

		mockPolicyRepo.On("FindPolicyRules", mock.Anything, "docs", "update").Return([]*model.PolicyRule{}, nil)

		payload := map[string]interface{}{
			"subject_id": "user_1",
			"action":     "update",
			"resource": map[string]interface{}{
				"resource_id":   "doc_1",
				"resource_type": "docs",
			},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":false`)
	})

	t.Run("deny when subject role does not match rule condition", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("GetSubject", mock.Anything, "user_1").Return(&model.Subject{
			UserID:   "user_1",
			Role:     "viewer",
			Status:   "active",
			GroupIDs: []string{},
		}, nil)

		mockPolicyRepo.On("FindPolicyRules", mock.Anything, "docs", "update").Return([]*model.PolicyRule{
			{
				Name:         "only editors can update",
				ResourceType: "docs",
				Action:       "update",
				Effect:       model.EffectAllow,
				Priority:     10,
				Conditions: model.ConditionSet{
					Subject: []model.Condition{
						{Field: "role", Operator: "in", Value: []interface{}{"editor", "admin", "owner"}},
					},
				},
				Enabled: true,
			},
		}, nil)

		payload := map[string]interface{}{
			"subject_id": "user_1",
			"action":     "update",
			"resource": map[string]interface{}{
				"resource_id":   "doc_1",
				"resource_type": "docs",
			},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":false`)
	})

	t.Run("deny rule takes precedence over allow at same priority", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("GetSubject", mock.Anything, "user_1").Return(&model.Subject{
			UserID:           "user_1",
			Role:             "editor",
			Status:           "active",
			SensitivityLevel: "restricted",
			GroupIDs:         []string{},
		}, nil)

		mockPolicyRepo.On("FindPolicyRules", mock.Anything, "docs", "update").Return([]*model.PolicyRule{
			{
				Name:         "editors can update",
				ResourceType: "docs",
				Action:       "update",
				Effect:       model.EffectAllow,
				Priority:     10,
				Conditions: model.ConditionSet{
					Subject: []model.Condition{
						{Field: "role", Operator: "eq", Value: "editor"},
					},
				},
				Enabled: true,
			},
			{
				Name:         "deny restricted users",
				ResourceType: "docs",
				Action:       "update",
				Effect:       model.EffectDeny,
				Priority:     10,
				Conditions: model.ConditionSet{
					Subject: []model.Condition{
						{Field: "sensitivity_level", Operator: "eq", Value: "restricted"},
					},
				},
				Enabled: true,
			},
		}, nil)

		payload := map[string]interface{}{
			"subject_id": "user_1",
			"action":     "update",
			"resource": map[string]interface{}{
				"resource_id":   "doc_1",
				"resource_type": "docs",
			},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":false`)
		assert.Contains(t, rec.Body.String(), `denied by rule`)
	})

	t.Run("deny when subject not found", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("GetSubject", mock.Anything, "unknown_user").Return(nil, nil)

		payload := map[string]interface{}{
			"subject_id": "unknown_user",
			"action":     "read",
			"resource": map[string]interface{}{
				"resource_id":   "doc_1",
				"resource_type": "docs",
			},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "u1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":false`)
		assert.Contains(t, rec.Body.String(), `subject not found`)
	})

	t.Run("return 401 when no auth header", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		payload := map[string]interface{}{
			"subject_id": "user_1",
			"action":     "read",
			"resource": map[string]interface{}{
				"resource_id":   "doc_1",
				"resource_type": "docs",
			},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("return 400 when action is missing", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		payload := map[string]interface{}{
			"subject_id": "user_1",
			"resource": map[string]interface{}{
				"resource_id":   "doc_1",
				"resource_type": "docs",
			},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("allow access with resource condition check", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("GetSubject", mock.Anything, "user_1").Return(&model.Subject{
			UserID:   "user_1",
			Role:     "admin",
			Status:   "active",
			GroupIDs: []string{},
		}, nil)

		mockPolicyRepo.On("FindPolicyRules", mock.Anything, "docs", "delete").Return([]*model.PolicyRule{
			{
				Name:         "admins can delete only draft docs",
				ResourceType: "docs",
				Action:       "delete",
				Effect:       model.EffectAllow,
				Priority:     10,
				Conditions: model.ConditionSet{
					Subject: []model.Condition{
						{Field: "role", Operator: "eq", Value: "admin"},
					},
					Resource: []model.Condition{
						{Field: "status", Operator: "eq", Value: "draft"},
					},
				},
				Enabled: true,
			},
		}, nil)

		payload := map[string]interface{}{
			"subject_id": "user_1",
			"action":     "delete",
			"resource": map[string]interface{}{
				"resource_id":   "doc_1",
				"resource_type": "docs",
				"status":        "draft",
			},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":true`)
	})

	t.Run("allow access with custom attribute condition", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("GetSubject", mock.Anything, "user_1").Return(&model.Subject{
			UserID:   "user_1",
			Role:     "editor",
			Status:   "active",
			GroupIDs: []string{},
			CustomAttrs: []model.CustomAttr{
				{Key: "team", Value: "engineering"},
			},
		}, nil)

		mockPolicyRepo.On("FindPolicyRules", mock.Anything, "docs", "read").Return([]*model.PolicyRule{
			{
				Name:         "engineering team can read",
				ResourceType: "docs",
				Action:       "read",
				Effect:       model.EffectAllow,
				Priority:     10,
				Conditions: model.ConditionSet{
					Subject: []model.Condition{
						{Field: "custom.team", Operator: "eq", Value: "engineering"},
					},
				},
				Enabled: true,
			},
		}, nil)

		payload := map[string]interface{}{
			"subject_id": "user_1",
			"action":     "read",
			"resource": map[string]interface{}{
				"resource_id":   "doc_1",
				"resource_type": "docs",
			},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":true`)
	})
}

func TestPostBatchCheckAccess(t *testing.T) {
	apiPath := "/api/v1/access/check/batch"

	t.Run("batch check with mixed results", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("GetSubject", mock.Anything, "user_1").Return(&model.Subject{
			UserID:   "user_1",
			Role:     "editor",
			Status:   "active",
			GroupIDs: []string{"group_a"},
		}, nil)

		// doc_1: has allowed_group_ids including group_a → proceed to rules
		// doc_2: has denied_group_ids including group_a → deny

		mockPolicyRepo.On("FindPolicyRules", mock.Anything, "docs", "read").Return([]*model.PolicyRule{
			{
				Name:         "active users can read",
				ResourceType: "docs",
				Action:       "read",
				Effect:       model.EffectAllow,
				Priority:     10,
				Conditions: model.ConditionSet{
					Subject: []model.Condition{
						{Field: "status", Operator: "eq", Value: "active"},
					},
				},
				Enabled: true,
			},
		}, nil)

		payload := map[string]interface{}{
			"subject_id": "user_1",
			"action":     "read",
			"resources": []map[string]interface{}{
				{
					"resource_id":   "doc_1",
					"resource_type": "docs",
				},
				{
					"resource_id":      "doc_2",
					"resource_type":    "docs",
					"denied_group_ids": []string{"group_a"},
				},
			},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		// doc_1 should be allowed, doc_2 should be denied
		assert.Contains(t, rec.Body.String(), `"doc_1"`)
		assert.Contains(t, rec.Body.String(), `"doc_2"`)
	})

	t.Run("return 400 when resources is empty", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		payload := map[string]interface{}{
			"subject_id": "user_1",
			"action":     "read",
			"resources":  []map[string]interface{}{},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}
