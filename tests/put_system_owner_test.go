package tests

import (
	"errors"
	"net/http"
	"testing"

	"rbac7/internal/rbac/handler"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Reuse MockRepo structure but we must define methods on it LOCALLY to this test file
// if we want to avoid redeclaration issues or just define a local mock type.
// Since Go doesn't allow method redeclaration in same package if in same file set?
// Actually different files in same package same struct name is fine if they are essentially same type,
// but redeclaring method in different files for same type?
// It's safer to define a distinct MockRepo for this test or share one in helper.
// Let's define `PutOwnerMockRepo` to avoid conflicts.

// PutOwnerMockRepo usage is replaced by shared MockRBACRepository in mock_repo.go

func TestPutSystemOwner(t *testing.T) {
	t.Run("transfer system owner old owner becomes admin (implied) and return 200", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/user_roles/owner_admin", h.PutSystemOwner)

		ownerRole := &model.UserRole{UserID: "owner_1", Role: model.RoleSystemOwner}
		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(ownerRole, nil)
		mockRepo.On("TransferSystemOwner", mock.Anything, "NS_1", "owner_1", "new_owner", "owner_1").Return(nil)

		reqBody := model.SystemOwnerUpsertRequest{UserID: "new_owner", Namespace: "ns_1"}
		headers := map[string]string{"authentication": "Bearer t", "x-user-id": "owner_1"}

		rec := PerformRequest(e, http.MethodPut, "/user_roles/owner_admin", reqBody, headers)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("transfer system owner missing new user_id and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/user_roles/owner_400", h.PutSystemOwner)

		reqBody := model.SystemOwnerUpsertRequest{UserID: "", Namespace: "ns_1"}
		headers := map[string]string{"authentication": "Bearer t", "x-user-id": "owner_1"}

		rec := PerformRequest(e, http.MethodPut, "/user_roles/owner_400", reqBody, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("transfer system owner missing namespace and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/user_roles/owner_400", h.PutSystemOwner)

		reqBody := model.SystemOwnerUpsertRequest{UserID: "new_owner", Namespace: ""}
		headers := map[string]string{"authentication": "Bearer t", "x-user-id": "owner_1"}

		rec := PerformRequest(e, http.MethodPut, "/user_roles/owner_400", reqBody, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("transfer system owner to same user_id and return 400", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/user_roles/owner_same", h.PutSystemOwner)

		reqBody := model.SystemOwnerUpsertRequest{UserID: "owner_1", Namespace: "ns_1"}
		headers := map[string]string{"authentication": "Bearer t", "x-user-id": "owner_1"}

		rec := PerformRequest(e, http.MethodPut, "/user_roles/owner_same", reqBody, headers)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("transfer system owner unauthorized and return 401", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/user_roles/owner_401", h.PutSystemOwner)

		reqBody := model.SystemOwnerUpsertRequest{UserID: "u", Namespace: "ns"}
		rec := PerformRequest(e, http.MethodPut, "/user_roles/owner_401", reqBody, map[string]string{})
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("transfer system owner forbidden (caller not current owner) and return 403", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/user_roles/owner_403", h.PutSystemOwner)

		// Permission Check -> False
		mockRepo.On("HasAnySystemRole", mock.Anything, "fake_owner", "NS_1", mock.Anything).Return(false, nil)
		// GetSystemOwner is NOT called if permission denied

		reqBody := model.SystemOwnerUpsertRequest{UserID: "new_owner", Namespace: "ns_1"}
		headers := map[string]string{"authentication": "Bearer t", "x-user-id": "fake_owner"}

		rec := PerformRequest(e, http.MethodPut, "/user_roles/owner_403", reqBody, headers)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("transfer system owner internal error and return 500", func(t *testing.T) {
		e := SetupServer()
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo)
		h := handler.NewSystemHandler(svc)
		e.PUT("/user_roles/owner_500", h.PutSystemOwner)

		ownerRole := &model.UserRole{UserID: "owner_1", Role: model.RoleSystemOwner}
		mockRepo.On("HasAnySystemRole", mock.Anything, "owner_1", "NS_1", mock.Anything).Return(true, nil)
		mockRepo.On("GetSystemOwner", mock.Anything, "NS_1").Return(ownerRole, nil)
		mockRepo.On("TransferSystemOwner", mock.Anything, "NS_1", "owner_1", "new_owner", "owner_1").Return(errors.New("db error"))

		reqBody := model.SystemOwnerUpsertRequest{UserID: "new_owner", Namespace: "ns_1"}
		headers := map[string]string{"authentication": "Bearer t", "x-user-id": "owner_1"}

		rec := PerformRequest(e, http.MethodPut, "/user_roles/owner_500", reqBody, headers)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
