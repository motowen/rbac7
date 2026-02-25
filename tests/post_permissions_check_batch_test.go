package tests

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"rbac7/internal/rbac/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestPostPermissionsCheckBatch(t *testing.T) {
	apiPath := "/api/v1/permissions/check/batch"

	t.Run("batch check all public (no whitelist) returns all true", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// All widgets have no whitelist (count == 0) => public access
		mockRepo.On("CountResourceRoles", mock.Anything, "lw_1", "library_widget").Return(int64(0), nil)
		mockRepo.On("CountResourceRoles", mock.Anything, "lw_2", "library_widget").Return(int64(0), nil)
		mockRepo.On("CountResourceRoles", mock.Anything, "lw_3", "library_widget").Return(int64(0), nil)

		payload := map[string]interface{}{
			"permission":    "resource.library_widget.read",
			"resource_type": "library_widget",
			"resource_ids":  []string{"lw_1", "lw_2", "lw_3"},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusOK, rec.Code)

		var resp model.BatchCheckPermissionResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, map[string]bool{"lw_1": true, "lw_2": true, "lw_3": true}, resp.Results)
	})

	t.Run("batch check mixed access returns correct results", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// lw_1: no whitelist => public (true)
		mockRepo.On("CountResourceRoles", mock.Anything, "lw_1", "library_widget").Return(int64(0), nil)
		// lw_2: has whitelist, user IS on it => allowed (true)
		mockRepo.On("CountResourceRoles", mock.Anything, "lw_2", "library_widget").Return(int64(2), nil)
		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "lw_2", "library_widget", mock.Anything).Return(true, nil)
		// lw_3: has whitelist, user NOT on it => denied (false)
		mockRepo.On("CountResourceRoles", mock.Anything, "lw_3", "library_widget").Return(int64(1), nil)
		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "lw_3", "library_widget", mock.Anything).Return(false, nil)

		payload := map[string]interface{}{
			"permission":    "resource.library_widget.read",
			"resource_type": "library_widget",
			"resource_ids":  []string{"lw_1", "lw_2", "lw_3"},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusOK, rec.Code)

		var resp model.BatchCheckPermissionResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, map[string]bool{"lw_1": true, "lw_2": true, "lw_3": false}, resp.Results)
	})

	t.Run("batch check all denied returns all false", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// All have whitelist, user not on any
		mockRepo.On("CountResourceRoles", mock.Anything, "lw_1", "library_widget").Return(int64(3), nil)
		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "lw_1", "library_widget", mock.Anything).Return(false, nil)
		mockRepo.On("CountResourceRoles", mock.Anything, "lw_2", "library_widget").Return(int64(1), nil)
		mockRepo.On("HasAnyResourceRole", mock.Anything, "user_1", "lw_2", "library_widget", mock.Anything).Return(false, nil)

		payload := map[string]interface{}{
			"permission":    "resource.library_widget.read",
			"resource_type": "library_widget",
			"resource_ids":  []string{"lw_1", "lw_2"},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusOK, rec.Code)

		var resp model.BatchCheckPermissionResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, map[string]bool{"lw_1": false, "lw_2": false}, resp.Results)
	})

	t.Run("batch check with single resource_id", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("CountResourceRoles", mock.Anything, "lw_1", "library_widget").Return(int64(0), nil)

		payload := map[string]interface{}{
			"permission":    "resource.library_widget.read",
			"resource_type": "library_widget",
			"resource_ids":  []string{"lw_1"},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusOK, rec.Code)

		var resp model.BatchCheckPermissionResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, map[string]bool{"lw_1": true}, resp.Results)
	})

	t.Run("batch check missing permission returns 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]interface{}{
			"resource_type": "library_widget",
			"resource_ids":  []string{"lw_1"},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("batch check missing resource_type returns 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]interface{}{
			"permission":   "resource.library_widget.read",
			"resource_ids": []string{"lw_1"},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("batch check empty resource_ids returns 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]interface{}{
			"permission":    "resource.library_widget.read",
			"resource_type": "library_widget",
			"resource_ids":  []string{},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("batch check resource_ids with empty string returns 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]interface{}{
			"permission":    "resource.library_widget.read",
			"resource_type": "library_widget",
			"resource_ids":  []string{"lw_1", ""},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("batch check resource_ids with duplicates returns 400", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]interface{}{
			"permission":    "resource.library_widget.read",
			"resource_type": "library_widget",
			"resource_ids":  []string{"lw_1", "lw_1"},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("batch check unauthorized returns 401", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		payload := map[string]interface{}{
			"permission":    "resource.library_widget.read",
			"resource_type": "library_widget",
			"resource_ids":  []string{"lw_1"},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, nil) // No Auth
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("batch check internal error returns 500", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("CountResourceRoles", mock.Anything, "lw_1", "library_widget").Return(int64(0), errors.New("db error"))

		payload := map[string]interface{}{
			"permission":    "resource.library_widget.read",
			"resource_type": "library_widget",
			"resource_ids":  []string{"lw_1"},
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, payload, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
