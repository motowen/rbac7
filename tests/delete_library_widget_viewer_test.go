package tests

import (
	"errors"
	"net/http"
	"rbac7/internal/rbac/model"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.mongodb.org/mongo-driver/mongo"
)

func TestDeleteLibraryWidgetViewer(t *testing.T) {
	// API path (middleware uses full path with /api/v1 prefix)
	apiPath := "/api/v1/user_roles/library_widgets"

	t.Run("delete viewer success", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: caller must have platform.system.remove_member in namespace
		// Note: Use uppercase NS_1 to match what middleware extracts from query
		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		// Service: delete the role
		mockRepo.On("DeleteUserRole", mock.Anything, "NS_1", "u_1", "resource", "lw_1", "library_widget", "owner_1").Return(nil)

		// Use uppercase namespace to match middleware extraction
		rec := PerformRequest(e, http.MethodDelete, apiPath+"?user_id=u_1&resource_id=lw_1&namespace=NS_1", nil, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"status":"success"`)
	})

	t.Run("delete viewer not found returns success (idempotent)", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("DeleteUserRole", mock.Anything, "NS_1", "u_1", "resource", "lw_1", "library_widget", "owner_1").Return(mongo.ErrNoDocuments)

		rec := PerformRequest(e, http.MethodDelete, apiPath+"?user_id=u_1&resource_id=lw_1&namespace=NS_1", nil, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("fail validation empty user_id", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC middleware passes (namespace provided), validation fails in handler
		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		rec := PerformRequest(e, http.MethodDelete, apiPath+"?user_id=&resource_id=lw_1&namespace=NS_1", nil, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("fail validation empty resource_id", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		rec := PerformRequest(e, http.MethodDelete, apiPath+"?user_id=u_1&resource_id=&namespace=NS_1", nil, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("fail validation empty namespace", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// Middleware can't extract namespace, validation fails in handler
		mockRepo.On("HasAnySystemRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()

		rec := PerformRequest(e, http.MethodDelete, apiPath+"?user_id=u_1&resource_id=lw_1&namespace=", nil, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("forbidden caller lacks remove_member permission", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: caller lacks permission
		mockRepo.On("HasAnySystemRole", mock.Anything, "viewer_1", "NS_1", mock.Anything).Return(false, nil)

		rec := PerformRequest(e, http.MethodDelete, apiPath+"?user_id=u_1&resource_id=lw_1&namespace=NS_1", nil, map[string]string{"x-user-id": "viewer_1"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("unauthorized no x-user-id header", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// RBAC Middleware: no caller ID
		rec := PerformRequest(e, http.MethodDelete, apiPath+"?user_id=u_1&resource_id=lw_1&namespace=NS_1", nil, map[string]string{})
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("internal error return 500", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("DeleteUserRole", mock.Anything, "NS_1", "u_1", "resource", "lw_1", "library_widget", "owner_1").Return(errors.New("db error"))

		rec := PerformRequest(e, http.MethodDelete, apiPath+"?user_id=u_1&resource_id=lw_1&namespace=NS_1", nil, map[string]string{"x-user-id": "owner_1"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

func TestDeleteLibraryWidgetViewerMeEndpoint(t *testing.T) {
	// Test the /user_roles/me endpoint for library_widget
	apiPath := "/api/v1/user_roles/me"

	t.Run("get my library_widget roles", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		e := SetupServerWithMiddleware(mockRepo)

		// FindUserRoles returns user's roles
		mockRepo.On("FindUserRoles", mock.Anything, mock.Anything).Return([]*model.UserRole{
			{UserID: "user_1", Role: "viewer", Scope: "resource", ResourceID: "lw_1", ResourceType: "library_widget"},
		}, nil)

		rec := PerformRequest(e, http.MethodGet, apiPath+"?scope=resource&resource_type=library_widget", nil, map[string]string{"x-user-id": "user_1"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
