package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"system/internal/system/client"
	"system/internal/system/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateSystem(t *testing.T) {
	t.Run("success - moderator creates system with owner", func(t *testing.T) {
		// Setup mock RBAC server
		rbacServer := CreateMockRBACServer(
			func(permission, namespace string) bool {
				return permission == "platform.system.create"
			},
			func(ownerID, namespace string) error {
				return nil
			},
			nil,
		)
		defer rbacServer.Close()

		// Setup mock repository
		mockRepo := &MockSystemRepository{
			GetSystemByNamespaceFunc: func(ctx context.Context, namespace string) (*model.System, error) {
				return nil, nil // namespace not exists
			},
			CreateSystemFunc: func(ctx context.Context, system *model.System) error {
				return nil
			},
		}

		// Setup GraphQL server
		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMockRepo(mockRepo, rbacClient)

		// Perform request
		query := `mutation {
			createSystem(namespace: "TEST_NS", name: "Test System", description: "A test", owner: "user_owner") {
				namespace
				name
			}
		}`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "moderator"})

		assert.Equal(t, http.StatusOK, rec.Code)
		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)

		var data struct {
			CreateSystem struct {
				Namespace string `json:"namespace"`
				Name      string `json:"name"`
			} `json:"createSystem"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Equal(t, "TEST_NS", data.CreateSystem.Namespace)
		assert.Equal(t, "Test System", data.CreateSystem.Name)
	})

	t.Run("forbidden - no permission to create", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(
			func(permission, namespace string) bool {
				return false // no permission
			},
			nil, nil,
		)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMockRepo(mockRepo, rbacClient)

		query := `mutation {
			createSystem(namespace: "TEST_NS", name: "Test", owner: "user") {
				namespace
			}
		}`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		require.NotEmpty(t, resp.Errors)
		assert.Contains(t, resp.Errors[0].Message, "forbidden")
	})

	t.Run("error - namespace already exists", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(
			func(permission, namespace string) bool { return true },
			nil, nil,
		)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{
			GetSystemByNamespaceFunc: func(ctx context.Context, namespace string) (*model.System, error) {
				return &model.System{Namespace: namespace}, nil // exists
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMockRepo(mockRepo, rbacClient)

		query := `mutation {
			createSystem(namespace: "EXISTING", name: "Test", owner: "user") {
				namespace
			}
		}`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "moderator"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		require.NotEmpty(t, resp.Errors)
		assert.Contains(t, resp.Errors[0].Message, "namespace already exists")
	})

	t.Run("unauthorized - missing x-user-id header", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMockRepo(mockRepo, rbacClient)

		query := `mutation { createSystem(namespace: "NS", name: "Test", owner: "u") { namespace } }`
		rec := PerformGraphQL(e, query, nil, nil) // no headers

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		require.NotEmpty(t, resp.Errors)
		assert.Contains(t, resp.Errors[0].Message, "unauthorized")
	})
}

func TestUpdateSystem(t *testing.T) {
	t.Run("success - owner updates system", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(
			func(permission, namespace string) bool {
				return permission == "platform.system.update" && namespace == "TEST_NS"
			},
			nil, nil,
		)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{
			UpdateSystemFunc: func(ctx context.Context, namespace string, name, description *string) (*model.System, error) {
				return &model.System{
					Namespace:   namespace,
					Name:        *name,
					Description: "updated",
				}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMockRepo(mockRepo, rbacClient)

		query := `mutation {
			updateSystem(namespace: "TEST_NS", name: "New Name") {
				namespace
				name
			}
		}`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "owner"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)
	})

	t.Run("forbidden - no update permission", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(
			func(permission, namespace string) bool { return false },
			nil, nil,
		)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMockRepo(mockRepo, rbacClient)

		query := `mutation { updateSystem(namespace: "NS", name: "New") { namespace } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "viewer"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		require.NotEmpty(t, resp.Errors)
		assert.Contains(t, resp.Errors[0].Message, "forbidden")
	})
}

func TestSystemMe(t *testing.T) {
	t.Run("success - returns user systems with roles", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(
			nil, nil,
			func(callerID string) []client.UserRole {
				return []client.UserRole{
					{Namespace: "NS1", Role: "owner"},
					{Namespace: "NS2", Role: "admin"},
				}
			},
		)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{
			GetSystemsByNamespacesFunc: func(ctx context.Context, namespaces []string) ([]*model.System, error) {
				return []*model.System{
					{Namespace: "NS1", Name: "System 1", Description: "Desc 1"},
					{Namespace: "NS2", Name: "System 2", Description: "Desc 2"},
				}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMockRepo(mockRepo, rbacClient)

		query := `query { systemMe { namespace name role } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)

		var data struct {
			SystemMe []struct {
				Namespace string `json:"namespace"`
				Name      string `json:"name"`
				Role      string `json:"role"`
			} `json:"systemMe"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Len(t, data.SystemMe, 2)
	})

	t.Run("success - returns empty when user has no roles", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(
			nil, nil,
			func(callerID string) []client.UserRole {
				return []client.UserRole{}
			},
		)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMockRepo(mockRepo, rbacClient)

		query := `query { systemMe { namespace } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "newuser"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)
	})
}

func TestSystemDetail(t *testing.T) {
	t.Run("success - returns system detail", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(
			func(permission, namespace string) bool {
				return permission == "platform.system.read" && namespace == "TEST_NS"
			},
			nil, nil,
		)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{
			GetSystemByNamespaceFunc: func(ctx context.Context, namespace string) (*model.System, error) {
				return &model.System{
					Namespace:   namespace,
					Name:        "Test System",
					Description: "A test system",
				}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMockRepo(mockRepo, rbacClient)

		query := `query { systemDetail(namespace: "TEST_NS") { namespace name description } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)

		var data struct {
			SystemDetail struct {
				Namespace   string  `json:"namespace"`
				Name        string  `json:"name"`
				Description *string `json:"description"`
			} `json:"systemDetail"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Equal(t, "TEST_NS", data.SystemDetail.Namespace)
		assert.Equal(t, "Test System", data.SystemDetail.Name)
	})

	t.Run("forbidden - no read permission", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(
			func(permission, namespace string) bool { return false },
			nil, nil,
		)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMockRepo(mockRepo, rbacClient)

		query := `query { systemDetail(namespace: "SECRET") { namespace } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "outsider"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		require.NotEmpty(t, resp.Errors)
		assert.Contains(t, resp.Errors[0].Message, "forbidden")
	})

	t.Run("returns null - system not found", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(
			func(permission, namespace string) bool { return true },
			nil, nil,
		)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{
			GetSystemByNamespaceFunc: func(ctx context.Context, namespace string) (*model.System, error) {
				return nil, nil // not found
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMockRepo(mockRepo, rbacClient)

		query := `query { systemDetail(namespace: "NONEXISTENT") { namespace } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)
		// Data should be null for non-existent system
	})
}
