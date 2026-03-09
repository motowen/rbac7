package tests

import (
	"context"
	"testing"

	"rbac7/internal/rbac/identity"
	"rbac7/internal/rbac/model"
	"rbac7/internal/rbac/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestCallerContext(t *testing.T) {
	t.Run("stores trusted caller fields in context", func(t *testing.T) {
		caller := identity.CallerContext{
			UserID:       "user_ctx",
			UserType:     model.UserTypeMember,
			ActiveTenant: "NS_1",
			OrgIDs:       []string{"org_1", "org_2"},
		}

		ctx := identity.WithCallerContext(context.Background(), caller)
		got, ok := identity.CallerFromContext(ctx)

		assert.True(t, ok)
		assert.Equal(t, caller.UserID, got.UserID)
		assert.Equal(t, caller.UserType, got.UserType)
		assert.Equal(t, caller.ActiveTenant, got.ActiveTenant)
		assert.Equal(t, caller.OrgIDs, got.OrgIDs)
	})

	t.Run("assign system owner uses caller from context when caller id is empty", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo, mockRepo)

		caller := identity.CallerContext{
			UserID:       "user_ctx",
			UserType:     model.UserTypeMember,
			ActiveTenant: "NS_1",
			OrgIDs:       []string{"org_1", "org_2"},
		}
		ctx := identity.WithCallerContext(context.Background(), caller)

		mockRepo.
			On("CreateUserRole", ctx, mock.MatchedBy(func(role *model.UserRole) bool {
				return role.UserID == "target_user" &&
					role.Role == model.RoleSystemOwner &&
					role.Scope == model.ScopeSystem &&
					role.Namespace == "NS_1" &&
					role.CreatedBy == caller.UserID &&
					role.UpdatedBy == caller.UserID
			})).
			Return(nil).
			Once()

		err := svc.AssignSystemOwner(ctx, "", model.AssignSystemOwnerReq{
			UserID:    "target_user",
			Namespace: "NS_1",
		})

		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})

	t.Run("permission checks use caller from context when caller id is empty", func(t *testing.T) {
		mockRepo := new(MockRBACRepository)
		svc := service.NewService(mockRepo, mockRepo)

		caller := identity.CallerContext{
			UserID:       "user_ctx",
			UserType:     model.UserTypeMember,
			ActiveTenant: "NS_1",
			OrgIDs:       []string{"org_1", "org_2"},
		}
		ctx := identity.WithCallerContext(context.Background(), caller)

		mockRepo.
			On("HasAnySystemRole", ctx, caller.UserID, "NS_1", mock.Anything).
			Return(true, nil).
			Once()

		allowed, err := svc.CheckPermission(ctx, "", model.CheckPermissionReq{
			Permission: model.PermPlatformSystemRead,
			Scope:      model.ScopeSystem,
			Namespace:  "NS_1",
		})

		assert.NoError(t, err)
		assert.True(t, allowed)
		mockRepo.AssertExpectations(t)
	})
}
