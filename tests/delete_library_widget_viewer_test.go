package tests

import (
	"errors"
	"net/http"
	"rbac7/internal/rbac/handler"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/service"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.mongodb.org/mongo-driver/mongo"
)

func TestDeleteLibraryWidgetViewer(t *testing.T) {
	path := "/user_roles/library_widgets"

	t.Run("delete viewer success", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE(path, h.DeleteLibraryWidgetViewer)

		// Permission Check: caller has platform.system.remove_member in namespace
		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("DeleteUserRole", mock.Anything, "NS_1", "u_1", "resource", "lw_1", "library_widget", "owner_1").Return(nil)

		reqBody := model.DeleteLibraryWidgetViewerReq{
			UserID:     "u_1",
			ResourceID: "lw_1",
			Namespace:  "ns_1",
		}
		rec := PerformRequest(e, http.MethodDelete, path, reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"status":"success"`)
	})

	t.Run("delete viewer not found returns success (idempotent)", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE(path, h.DeleteLibraryWidgetViewer)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("DeleteUserRole", mock.Anything, "NS_1", "u_1", "resource", "lw_1", "library_widget", "owner_1").Return(mongo.ErrNoDocuments)

		reqBody := model.DeleteLibraryWidgetViewerReq{
			UserID:     "u_1",
			ResourceID: "lw_1",
			Namespace:  "ns_1",
		}
		rec := PerformRequest(e, http.MethodDelete, path, reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("fail validation empty user_id", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE(path, h.DeleteLibraryWidgetViewer)

		reqBody := model.DeleteLibraryWidgetViewerReq{
			UserID:     "",
			ResourceID: "lw_1",
			Namespace:  "ns_1",
		}
		rec := PerformRequest(e, http.MethodDelete, path, reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("fail validation empty resource_id", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE(path, h.DeleteLibraryWidgetViewer)

		reqBody := model.DeleteLibraryWidgetViewerReq{
			UserID:     "u_1",
			ResourceID: "",
			Namespace:  "ns_1",
		}
		rec := PerformRequest(e, http.MethodDelete, path, reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("fail validation empty namespace", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE(path, h.DeleteLibraryWidgetViewer)

		reqBody := model.DeleteLibraryWidgetViewerReq{
			UserID:     "u_1",
			ResourceID: "lw_1",
			Namespace:  "",
		}
		rec := PerformRequest(e, http.MethodDelete, path, reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("forbidden caller lacks remove_member permission", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE(path, h.DeleteLibraryWidgetViewer)

		mockRepo.On("HasAnySystemRole", mock.Anything, "viewer_1", "NS_1", mock.Anything).Return(false, nil)

		reqBody := model.DeleteLibraryWidgetViewerReq{
			UserID:     "u_1",
			ResourceID: "lw_1",
			Namespace:  "ns_1",
		}
		rec := PerformRequest(e, http.MethodDelete, path, reqBody, map[string]string{"x-user-id": "viewer_1", "authentication": "t"})
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("unauthorized no auth header", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE(path, h.DeleteLibraryWidgetViewer)

		reqBody := model.DeleteLibraryWidgetViewerReq{
			UserID:     "u_1",
			ResourceID: "lw_1",
			Namespace:  "ns_1",
		}
		rec := PerformRequest(e, http.MethodDelete, path, reqBody, map[string]string{})
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("internal error return 500", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.DELETE(path, h.DeleteLibraryWidgetViewer)

		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("DeleteUserRole", mock.Anything, "NS_1", "u_1", "resource", "lw_1", "library_widget", "owner_1").Return(errors.New("db error"))

		reqBody := model.DeleteLibraryWidgetViewerReq{
			UserID:     "u_1",
			ResourceID: "lw_1",
			Namespace:  "ns_1",
		}
		rec := PerformRequest(e, http.MethodDelete, path, reqBody, map[string]string{"x-user-id": "owner_1", "authentication": "t"})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
