package abac

import (
	"net/http"
	"testing"

	"rbac7/internal/abac/model"
	"rbac7/internal/abac/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestPolicyRuleCRUD(t *testing.T) {
	t.Run("create policy rule successfully", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockPolicyRepo.On("CreatePolicyRule", mock.Anything, mock.Anything).Return(nil)

		payload := map[string]interface{}{
			"name":          "editors can read docs",
			"resource_type": "docs",
			"action":        "read",
			"effect":        "allow",
			"priority":      10,
			"enabled":       true,
			"conditions": map[string]interface{}{
				"subject": []map[string]interface{}{
					{"field": "role", "operator": "in", "value": []string{"editor", "admin"}},
				},
			},
		}
		rec := PerformRequest(e, http.MethodPost, "/api/v1/policies", payload, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusCreated, rec.Code)
	})

	t.Run("create policy rule with invalid effect", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		payload := map[string]interface{}{
			"name":          "bad rule",
			"resource_type": "docs",
			"action":        "read",
			"effect":        "invalid",
			"priority":      10,
		}
		rec := PerformRequest(e, http.MethodPost, "/api/v1/policies", payload, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("create policy rule missing name", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		payload := map[string]interface{}{
			"resource_type": "docs",
			"action":        "read",
			"effect":        "allow",
		}
		rec := PerformRequest(e, http.MethodPost, "/api/v1/policies", payload, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("list policy rules successfully", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockPolicyRepo.On("ListPolicyRules", mock.Anything, mock.Anything).Return([]*model.PolicyRule{
			{
				ID:           "rule_1",
				Name:         "editors can read",
				ResourceType: "docs",
				Action:       "read",
				Effect:       "allow",
				Priority:     10,
				Enabled:      true,
			},
		}, nil)

		rec := PerformRequest(e, http.MethodGet, "/api/v1/policies?resource_type=docs", nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"editors can read"`)
	})

	t.Run("update policy rule successfully", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockPolicyRepo.On("GetPolicyRule", mock.Anything, "rule_1").Return(&model.PolicyRule{
			ID:           "rule_1",
			Name:         "old name",
			ResourceType: "docs",
			Action:       "read",
			Effect:       "allow",
			Priority:     10,
			Enabled:      true,
		}, nil)
		mockPolicyRepo.On("UpdatePolicyRule", mock.Anything, mock.Anything).Return(nil)

		newName := "new name"
		payload := map[string]interface{}{
			"name": newName,
		}
		rec := PerformRequest(e, http.MethodPut, "/api/v1/policies/rule_1", payload, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("update policy rule not found", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockPolicyRepo.On("GetPolicyRule", mock.Anything, "unknown").Return(nil, nil)

		payload := map[string]interface{}{
			"name": "new name",
		}
		rec := PerformRequest(e, http.MethodPut, "/api/v1/policies/unknown", payload, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("delete policy rule successfully", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockPolicyRepo.On("DeletePolicyRule", mock.Anything, "rule_1").Return(nil)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/policies/rule_1", nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("delete policy rule not found", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockPolicyRepo.On("DeletePolicyRule", mock.Anything, "unknown").Return(repository.ErrNotFound)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/policies/unknown", nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestAttributeDefinitionCRUD(t *testing.T) {
	t.Run("create attribute definition successfully", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockPolicyRepo.On("CreateAttributeDefinition", mock.Anything, mock.Anything).Return(nil)

		payload := map[string]interface{}{
			"key":            "doc.sensitivity",
			"scope":          "resource",
			"resource_type":  "docs",
			"type":           "enum",
			"managed_by":     "app",
			"operators":      []string{"eq", "in"},
			"allowed_values": []string{"public", "internal", "restricted"},
		}
		rec := PerformRequest(e, http.MethodPost, "/api/v1/attributes", payload, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusCreated, rec.Code)
	})

	t.Run("create attribute definition invalid scope", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		payload := map[string]interface{}{
			"key":        "test",
			"scope":      "invalid",
			"type":       "string",
			"managed_by": "app",
			"operators":  []string{"eq"},
		}
		rec := PerformRequest(e, http.MethodPost, "/api/v1/attributes", payload, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("create attribute definition enum without allowed values", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		payload := map[string]interface{}{
			"key":        "test",
			"scope":      "resource",
			"type":       "enum",
			"managed_by": "app",
			"operators":  []string{"eq"},
		}
		rec := PerformRequest(e, http.MethodPost, "/api/v1/attributes", payload, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("list attribute definitions successfully", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockPolicyRepo.On("ListAttributeDefinitions", mock.Anything, "resource", "docs").Return([]*model.AttributeDefinition{
			{
				Key:          "doc.sensitivity",
				Scope:        "resource",
				ResourceType: "docs",
				Type:         "enum",
				ManagedBy:    "app",
			},
		}, nil)

		rec := PerformRequest(e, http.MethodGet, "/api/v1/attributes?scope=resource&resource_type=docs", nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"doc.sensitivity"`)
	})

	t.Run("delete attribute definition successfully", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockPolicyRepo.On("DeleteAttributeDefinition", mock.Anything, "doc.sensitivity", "resource").Return(nil)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/attributes/doc.sensitivity?scope=resource", nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("delete attribute definition not found", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockPolicyRepo.On("DeleteAttributeDefinition", mock.Anything, "unknown", "resource").Return(repository.ErrNotFound)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/attributes/unknown?scope=resource", nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}
