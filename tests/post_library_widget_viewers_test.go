package tests

import (
	"encoding/json"
	"errors"
	"net/http"
	"rbac7/internal/rbac/model"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestPostLibraryWidgetViewers(t *testing.T) {
	apiPath := "/api/v1/user_roles/library_widgets/batch"

	t.Run("assign viewers success", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission check
		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)

		// Service: bulk upsert
		mockRepo.On("BulkUpsertUserRoles", mock.Anything, mock.MatchedBy(func(roles []*model.UserRole) bool {
			return len(roles) == 2 &&
				roles[0].Role == "viewer" &&
				roles[0].ResourceType == "library_widget" &&
				roles[0].Namespace == "NS_1"
		})).Return(&model.BatchUpsertResult{SuccessCount: 2, FailedCount: 0}, nil)

		reqBody := model.AssignLibraryWidgetViewersReq{
			UserIDs:    []string{"u_1", "u_2"},
			ResourceID: "lw_1",
			Namespace:  "NS_1",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusOK, rec.Code)

		var result model.BatchUpsertResult
		json.Unmarshal(rec.Body.Bytes(), &result)
		assert.Equal(t, 2, result.SuccessCount)
		assert.Equal(t, 0, result.FailedCount)
	})

	t.Run("fail validation empty user_ids", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		reqBody := model.AssignLibraryWidgetViewersReq{
			UserIDs:    []string{},
			ResourceID: "lw_1",
			Namespace:  "NS_1",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("fail validation empty resource_id", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		reqBody := model.AssignLibraryWidgetViewersReq{
			UserIDs:    []string{"u_1"},
			ResourceID: "",
			Namespace:  "NS_1",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("fail validation empty namespace", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		reqBody := model.AssignLibraryWidgetViewersReq{
			UserIDs:    []string{"u_1"},
			ResourceID: "lw_1",
			Namespace:  "",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("forbidden caller lacks add_member permission", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: permission denied
		mockRepo.On("HasAnySystemRole", mock.Anything, "viewer_1", "NS_1", mock.Anything).Return(false, nil)

		reqBody := model.AssignLibraryWidgetViewersReq{
			UserIDs:    []string{"u_1"},
			ResourceID: "lw_1",
			Namespace:  "NS_1",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "viewer_1"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("unauthorized no x-user-id header", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		reqBody := model.AssignLibraryWidgetViewersReq{
			UserIDs:    []string{"u_1"},
			ResourceID: "lw_1",
			Namespace:  "NS_1",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("internal error return 500", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("BulkUpsertUserRoles", mock.Anything, mock.Anything).Return(nil, errors.New("db error"))

		reqBody := model.AssignLibraryWidgetViewersReq{
			UserIDs:    []string{"u_1"},
			ResourceID: "lw_1",
			Namespace:  "NS_1",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("partial success some users fail", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("BulkUpsertUserRoles", mock.Anything, mock.MatchedBy(func(roles []*model.UserRole) bool {
			return len(roles) == 3
		})).Return(&model.BatchUpsertResult{
			SuccessCount: 2,
			FailedCount:  1,
			FailedUsers: []model.FailedUserInfo{
				{UserID: "u_fail", Reason: "error"},
			},
		}, nil)

		reqBody := model.AssignLibraryWidgetViewersReq{
			UserIDs:    []string{"u_1", "u_fail", "u_2"},
			ResourceID: "lw_1",
			Namespace:  "NS_1",
		}
		rec := PerformRequest(e, http.MethodPost, apiPath, reqBody, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusOK, rec.Code)

		var result model.BatchUpsertResult
		json.Unmarshal(rec.Body.Bytes(), &result)
		assert.Equal(t, 2, result.SuccessCount)
		assert.Equal(t, 1, result.FailedCount)
	})
}
