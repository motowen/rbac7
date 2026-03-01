package tests

import (
	"encoding/json"
	"net/http"
	"testing"

	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestPostPermissionsCheckWithOrg(t *testing.T) {
	apiPath := "/api/v1/permissions/check"

	// Helper: build a full OrgUser with all fields
	validOrgUser := &repository.OrgUser{
		UserID:      "yjwenh",
		FunctionID:  "00R00000",
		FunctionID1: "00600000",
		DivisionID:  "0060D000",
		DeptID:      "00302T00",
		SectID:      "00302T0B",
	}

	t.Run("org system permission allowed via functionId role", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		mockOrgRepo := new(MockOrgUserRepository)
		e := SetupServerWithMiddlewareAndOrg(mockRepo, mockOrgRepo)

		// 1. Member check fails
		mockRepo.On("HasAnySystemRole", mock.Anything, "yjwenh", "", mock.Anything).Return(false, nil)
		// 2. Org lookup succeeds
		mockOrgRepo.On("GetOrgUser", mock.Anything, "yjwenh").Return(validOrgUser, nil)
		// 3. Find org roles: functionId has admin role
		mockRepo.On("FindUserRolesByUserIDs", mock.Anything,
			mock.MatchedBy(func(ids []string) bool { return len(ids) > 0 }),
			model.UserTypeOrg, model.ScopeSystem, "", "", "",
		).Return([]*model.UserRole{
			{UserID: "00R00000", UserType: model.UserTypeOrg, Role: model.RoleSystemAdmin},
		}, nil)

		payload := map[string]string{
			"permission": "platform.system.read",
			"scope":      "system",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "yjwenh"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":true`)
	})

	t.Run("org system permission denied - no matching org roles", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		mockOrgRepo := new(MockOrgUserRepository)
		e := SetupServerWithMiddlewareAndOrg(mockRepo, mockOrgRepo)

		// 1. Member check fails
		mockRepo.On("HasAnySystemRole", mock.Anything, "yjwenh", "", mock.Anything).Return(false, nil)
		// 2. Org lookup succeeds
		mockOrgRepo.On("GetOrgUser", mock.Anything, "yjwenh").Return(validOrgUser, nil)
		// 3. No org roles found
		mockRepo.On("FindUserRolesByUserIDs", mock.Anything,
			mock.MatchedBy(func(ids []string) bool { return len(ids) > 0 }),
			model.UserTypeOrg, model.ScopeSystem, "", "", "",
		).Return([]*model.UserRole{}, nil)

		payload := map[string]string{
			"permission": "platform.system.read",
			"scope":      "system",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "yjwenh"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":false`)
	})

	t.Run("org not found in org db - falls back to member check only", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		mockOrgRepo := new(MockOrgUserRepository)
		e := SetupServerWithMiddlewareAndOrg(mockRepo, mockOrgRepo)

		// 1. Member check fails
		mockRepo.On("HasAnySystemRole", mock.Anything, "unknown_user", "", mock.Anything).Return(false, nil)
		// 2. Org lookup: not found
		mockOrgRepo.On("GetOrgUser", mock.Anything, "unknown_user").Return(nil, nil)

		payload := map[string]string{
			"permission": "platform.system.read",
			"scope":      "system",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "unknown_user"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":false`)
	})

	t.Run("org resource permission allowed via divisionId role", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		mockOrgRepo := new(MockOrgUserRepository)
		e := SetupServerWithMiddlewareAndOrg(mockRepo, mockOrgRepo)

		// 1. Member resource check (dashboard has no special inheritance, CountResourceRoles not called here)
		mockRepo.On("HasAnyResourceRole", mock.Anything, "yjwenh", "dash_1", "dashboard", mock.Anything).Return(false, nil)
		// 2. Org lookup
		mockOrgRepo.On("GetOrgUser", mock.Anything, "yjwenh").Return(validOrgUser, nil)
		// 3. org role: divisionId has viewer role on dash_1
		mockRepo.On("FindUserRolesByUserIDs", mock.Anything,
			mock.MatchedBy(func(ids []string) bool { return len(ids) > 0 }),
			model.UserTypeOrg, model.ScopeResource, "", "dash_1", "dashboard",
		).Return([]*model.UserRole{
			{UserID: "0060D000", UserType: model.UserTypeOrg, Role: model.RoleResourceViewer},
		}, nil)

		payload := map[string]string{
			"permission":    "resource.dashboard.read",
			"scope":         "resource",
			"resource_id":   "dash_1",
			"resource_type": "dashboard",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "yjwenh"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":true`)
	})

	t.Run("org max role: multiple org roles, highest wins (admin > viewer)", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		mockOrgRepo := new(MockOrgUserRepository)
		e := SetupServerWithMiddlewareAndOrg(mockRepo, mockOrgRepo)

		// 1. Member check fails
		mockRepo.On("HasAnyResourceRole", mock.Anything, "yjwenh", "dash_1", "dashboard", mock.Anything).Return(false, nil)
		// 2. Org lookup
		mockOrgRepo.On("GetOrgUser", mock.Anything, "yjwenh").Return(validOrgUser, nil)
		// 3. Multiple org roles: viewer via sectId, admin via functionId → max = admin → has read permission
		mockRepo.On("FindUserRolesByUserIDs", mock.Anything,
			mock.MatchedBy(func(ids []string) bool { return len(ids) > 0 }),
			model.UserTypeOrg, model.ScopeResource, "", "dash_1", "dashboard",
		).Return([]*model.UserRole{
			{UserID: "00302T0B", UserType: model.UserTypeOrg, Role: model.RoleResourceViewer},
			{UserID: "00R00000", UserType: model.UserTypeOrg, Role: model.RoleResourceAdmin},
		}, nil)

		payload := map[string]string{
			"permission":    "resource.dashboard.read",
			"scope":         "resource",
			"resource_id":   "dash_1",
			"resource_type": "dashboard",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "yjwenh"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":true`)
	})

	t.Run("without org repo - behaves same as before (no org check)", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo) // no orgRepo

		mockRepo.On("HasAnySystemRole", mock.Anything, "user_1", "", mock.Anything).Return(false, nil)

		payload := map[string]string{
			"permission": "platform.system.read",
			"scope":      "system",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"allowed":false`)
	})
}

func TestPostPermissionsCheckBatchWithOrg(t *testing.T) {
	apiPath := "/api/v1/permissions/check/batch"

	validOrgUser := &repository.OrgUser{
		UserID:     "yjwenh",
		FunctionID: "00R00000",
		DivisionID: "0060D000",
		DeptID:     "00302T00",
		SectID:     "00302T0B",
	}

	t.Run("batch check: member denied but org allows for some resources", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		mockOrgRepo := new(MockOrgUserRepository)
		e := SetupServerWithMiddlewareAndOrg(mockRepo, mockOrgRepo)

		// lw_1: no whitelist → public (true, before org check)
		mockRepo.On("CountResourceRoles", mock.Anything, "lw_1", "library_widget").Return(int64(0), nil)
		// lw_2: has whitelist, member not on it → check org
		mockRepo.On("CountResourceRoles", mock.Anything, "lw_2", "library_widget").Return(int64(1), nil)
		mockRepo.On("HasAnyResourceRole", mock.Anything, "yjwenh", "lw_2", "library_widget", mock.Anything).Return(false, nil)

		// Org check for lw_2
		mockOrgRepo.On("GetOrgUser", mock.Anything, "yjwenh").Return(validOrgUser, nil)
		mockRepo.On("FindUserRolesByUserIDs", mock.Anything,
			mock.MatchedBy(func(ids []string) bool { return len(ids) > 0 }),
			model.UserTypeOrg, model.ScopeResource, "", "lw_2", "library_widget",
		).Return([]*model.UserRole{
			{UserID: "00R00000", UserType: model.UserTypeOrg, Role: model.RoleResourceViewer},
		}, nil)

		payload := map[string]interface{}{
			"permission":    "resource.library_widget.read",
			"resource_type": "library_widget",
			"resource_ids":  []string{"lw_1", "lw_2"},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "yjwenh"})
		assert.Equal(t, http.StatusOK, rec.Code)

		var resp model.BatchCheckPermissionResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, map[string]bool{"lw_1": true, "lw_2": true}, resp.Results)
	})
}
