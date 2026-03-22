package abac

import (
	"net/http"
	"testing"

	"rbac7/internal/abac/model"
	"rbac7/internal/abac/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSubjectCRUD(t *testing.T) {
	t.Run("create subject successfully", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("CreateSubject", mock.Anything, mock.Anything).Return(nil)

		payload := map[string]interface{}{
			"user_id": "user_1",
			"role":    "editor",
			"status":  "active",
			"orgs": []map[string]string{
				{"org_id": "org_1", "org_type": "department"},
			},
			"group_ids": []string{"group_a"},
		}
		rec := PerformRequest(e, http.MethodPost, "/api/v1/subjects", payload, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusCreated, rec.Code)
		assert.Contains(t, rec.Body.String(), `"status":"success"`)
	})

	t.Run("create subject conflict (duplicate)", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("CreateSubject", mock.Anything, mock.Anything).Return(repository.ErrDuplicate)

		payload := map[string]interface{}{
			"user_id": "user_1",
			"role":    "editor",
			"status":  "active",
		}
		rec := PerformRequest(e, http.MethodPost, "/api/v1/subjects", payload, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusConflict, rec.Code)
	})

	t.Run("create subject missing required fields", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		payload := map[string]interface{}{
			"user_id": "user_1",
			// missing role and status
		}
		rec := PerformRequest(e, http.MethodPost, "/api/v1/subjects", payload, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("get subject successfully", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("GetSubject", mock.Anything, "user_1").Return(&model.Subject{
			UserID:   "user_1",
			Role:     "editor",
			Status:   "active",
			GroupIDs: []string{"group_a"},
			Orgs:     []model.OrgMembership{{OrgID: "org_1", OrgType: "department"}},
		}, nil)

		rec := PerformRequest(e, http.MethodGet, "/api/v1/subjects/user_1", nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"user_id":"user_1"`)
		assert.Contains(t, rec.Body.String(), `"role":"editor"`)
	})

	t.Run("get subject not found", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("GetSubject", mock.Anything, "unknown").Return(nil, nil)

		rec := PerformRequest(e, http.MethodGet, "/api/v1/subjects/unknown", nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("update subject successfully", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("GetSubject", mock.Anything, "user_1").Return(&model.Subject{
			UserID:   "user_1",
			Role:     "editor",
			Status:   "active",
			GroupIDs: []string{},
			Orgs:     []model.OrgMembership{},
		}, nil)
		mockSubjectRepo.On("UpdateSubject", mock.Anything, mock.Anything).Return(nil)

		newRole := "admin"
		payload := map[string]interface{}{
			"role": newRole,
		}
		rec := PerformRequest(e, http.MethodPut, "/api/v1/subjects/user_1", payload, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("update subject not found", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("GetSubject", mock.Anything, "unknown").Return(nil, nil)

		payload := map[string]interface{}{
			"role": "admin",
		}
		rec := PerformRequest(e, http.MethodPut, "/api/v1/subjects/unknown", payload, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("delete subject successfully", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("DeleteSubject", mock.Anything, "user_1", "admin_1").Return(nil)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/subjects/user_1", nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("delete subject not found", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("DeleteSubject", mock.Anything, "unknown", "admin_1").Return(repository.ErrNotFound)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/subjects/unknown", nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("create subject without auth returns 401", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		payload := map[string]interface{}{
			"user_id": "user_1",
			"role":    "editor",
			"status":  "active",
		}
		rec := PerformRequest(e, http.MethodPost, "/api/v1/subjects", payload, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

func TestSubjectGroups(t *testing.T) {
	t.Run("add subject to group successfully", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("AddGroupToSubject", mock.Anything, "user_1", "group_b").Return(nil)

		payload := map[string]interface{}{
			"group_id": "group_b",
		}
		rec := PerformRequest(e, http.MethodPost, "/api/v1/subjects/user_1/groups", payload, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("add subject to group - subject not found", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("AddGroupToSubject", mock.Anything, "unknown", "group_b").Return(repository.ErrNotFound)

		payload := map[string]interface{}{
			"group_id": "group_b",
		}
		rec := PerformRequest(e, http.MethodPost, "/api/v1/subjects/unknown/groups", payload, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("remove subject from group successfully", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("RemoveGroupFromSubject", mock.Anything, "user_1", "group_b").Return(nil)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/subjects/user_1/groups/group_b", nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestSubjectOrgs(t *testing.T) {
	t.Run("upsert org membership successfully", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("UpsertOrgMembership", mock.Anything, "user_1", model.OrgMembership{OrgID: "org_1", OrgType: "department"}).Return(nil)

		payload := map[string]interface{}{
			"org": map[string]string{
				"org_id":   "org_1",
				"org_type": "department",
			},
		}
		rec := PerformRequest(e, http.MethodPut, "/api/v1/subjects/user_1/orgs", payload, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("remove org membership successfully", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		mockSubjectRepo.On("RemoveOrgMembership", mock.Anything, "user_1", "org_1").Return(nil)

		rec := PerformRequest(e, http.MethodDelete, "/api/v1/subjects/user_1/orgs/org_1", nil, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("upsert org missing required fields", func(t *testing.T) {
		mockSubjectRepo := new(MockABACRepository)
		mockPolicyRepo := new(MockPolicyRepository)
		e := SetupServer(mockSubjectRepo, mockPolicyRepo)

		payload := map[string]interface{}{
			"org": map[string]string{
				"org_id": "org_1",
				// missing org_type
			},
		}
		rec := PerformRequest(e, http.MethodPut, "/api/v1/subjects/user_1/orgs", payload, map[string]string{"x-user-id": "admin_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}
