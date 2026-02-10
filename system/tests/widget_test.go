package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"system/internal/system/client"
	"system/internal/system/model"
	"system/internal/system/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================
// Library Widget Tests
// ============================================

func TestCreateLibraryWidget(t *testing.T) {
	t.Run("success - creates library widget", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			CreateLibraryWidgetFunc: func(ctx context.Context, widget *model.LibraryWidget) (*model.LibraryWidget, error) {
				widget.ID = "widget-123"
				widget.CreatedAt = time.Now()
				widget.UpdatedAt = time.Now()
				return widget, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `mutation {
			createLibraryWidget(input: {
				name: "My Widget"
				version: "1.0.0"
				type: "table"
				typeVersion: "1.0"
			}) {
				id
				name
				version
				type
				status
			}
		}`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		assert.Equal(t, http.StatusOK, rec.Code)
		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)

		var data struct {
			CreateLibraryWidget struct {
				ID      string `json:"id"`
				Name    string `json:"name"`
				Version string `json:"version"`
				Type    string `json:"type"`
				Status  string `json:"status"`
			} `json:"createLibraryWidget"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Equal(t, "widget-123", data.CreateLibraryWidget.ID)
		assert.Equal(t, "My Widget", data.CreateLibraryWidget.Name)
		assert.Equal(t, "table", data.CreateLibraryWidget.Type)
		assert.Equal(t, "DRAFT", data.CreateLibraryWidget.Status)
	})
}

func TestUpdateLibraryWidget(t *testing.T) {
	t.Run("success - updates library widget", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:     id,
					Name:   "Old Widget",
					Status: model.StatusDraft,
				}, nil
			},
			UpdateLibraryWidgetFunc: func(ctx context.Context, id string, update *repository.LibraryWidgetUpdate) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:          id,
					Name:        "Updated Widget",
					Version:     "1.0.0",
					Type:        "chart",
					TypeVersion: "1.0",
					Status:      "published",
				}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `mutation {
			updateLibraryWidget(input: {id: "widget-123", name: "Updated Widget"}) {
				id
				status
			}
		}`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)

		var data struct {
			UpdateLibraryWidget struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"updateLibraryWidget"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Equal(t, "widget-123", data.UpdateLibraryWidget.ID)
		assert.Equal(t, "PUBLISHED", data.UpdateLibraryWidget.Status)
	})

	t.Run("error - widget not found", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			UpdateLibraryWidgetFunc: func(ctx context.Context, id string, update *repository.LibraryWidgetUpdate) (*model.LibraryWidget, error) {
				return nil, nil // not found
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `mutation { updateLibraryWidget(input: {id: "nonexistent"}) { id } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		require.NotEmpty(t, resp.Errors)
		assert.Contains(t, resp.Errors[0].Message, "not found")
	})
}

func TestTrashLibraryWidget(t *testing.T) {
	t.Run("success - trashes library widget", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:     id,
					Name:   "Widget To Trash",
					Status: model.StatusDraft,
				}, nil
			},
			UpdateLibraryWidgetStatusFunc: func(ctx context.Context, id string, status string, previousStatus string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:     id,
					Name:   "Widget To Trash",
					Status: status,
				}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `mutation { trashLibraryWidget(id: "widget-123") { id status } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)

		var data struct {
			TrashLibraryWidget struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"trashLibraryWidget"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Equal(t, "widget-123", data.TrashLibraryWidget.ID)
		assert.Equal(t, "TRASHED", data.TrashLibraryWidget.Status)
	})
}

func TestLibraryWidgets(t *testing.T) {
	t.Run("success - returns all library widgets", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetsFunc: func(ctx context.Context) ([]*model.LibraryWidget, error) {
				return []*model.LibraryWidget{
					{ID: "w1", Name: "Widget 1", Version: "1.0", Type: "table", TypeVersion: "1.0", Status: "published"},
					{ID: "w2", Name: "Widget 2", Version: "1.0", Type: "chart", TypeVersion: "1.0", Status: "draft"},
				}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `query { libraryWidgets { id name type status } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)

		var data struct {
			LibraryWidgets []struct {
				ID     string `json:"id"`
				Name   string `json:"name"`
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"libraryWidgets"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Len(t, data.LibraryWidgets, 2)
		assert.Equal(t, "w1", data.LibraryWidgets[0].ID)
		assert.Equal(t, "w2", data.LibraryWidgets[1].ID)
	})

	t.Run("success - returns empty array when no widgets", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetsFunc: func(ctx context.Context) ([]*model.LibraryWidget, error) {
				return []*model.LibraryWidget{}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `query { libraryWidgets { id } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)
	})
}

func TestLibraryWidget(t *testing.T) {
	t.Run("success - returns library widget by id", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:          id,
					Name:        "Test Widget",
					Version:     "1.0.0",
					Type:        "table",
					TypeVersion: "1.0",
					Status:      "published",
				}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `query { libraryWidget(id: "widget-123") { id name type } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)

		var data struct {
			LibraryWidget struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"libraryWidget"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Equal(t, "widget-123", data.LibraryWidget.ID)
	})

	t.Run("returns null - widget not found", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockRepo := &MockSystemRepository{}
		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return nil, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(mockRepo, mockWidgetRepo, rbacClient)

		query := `query { libraryWidget(id: "nonexistent") { id } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)
		// Data should contain null for libraryWidget
	})
}

// ============================================
// Dashboard Tests (New API)
// ============================================
// Note: Dashboard Widget tests have been removed as the API changed.
// New tests for the Dashboard API should be added in a separate file (dashboard_test.go)
// once the new API is stable.
