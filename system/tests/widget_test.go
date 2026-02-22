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

// ============================================
// Widget Versioning Tests
// ============================================

func TestUpdateLibraryWidget_PublishedCreatesChanged(t *testing.T) {
	t.Run("published widget creates changed copy and updates it", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		copyToChangedCalled := false
		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:      id,
					GroupID: id,
					Name:    "Published Widget",
					Status:  model.StatusPublished,
				}, nil
			},
			GetByGroupAndStatusFunc: func(ctx context.Context, groupID string, status string) (*model.LibraryWidget, error) {
				// No changed version exists yet
				return nil, nil
			},
			CopyToChangedFunc: func(ctx context.Context, groupID string) (*model.LibraryWidget, error) {
				copyToChangedCalled = true
				return &model.LibraryWidget{
					ID:      "changed-" + groupID,
					GroupID: groupID,
					Name:    "Published Widget",
					Status:  model.StatusChanged,
				}, nil
			},
			UpdateLibraryWidgetFunc: func(ctx context.Context, id string, update *repository.LibraryWidgetUpdate) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:      id,
					GroupID: "widget-123",
					Name:    "Updated Name",
					Status:  model.StatusChanged,
				}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(&MockSystemRepository{}, mockWidgetRepo, rbacClient)

		query := `mutation { updateLibraryWidget(input: {id: "widget-123", name: "Updated Name"}) { id name status } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)
		assert.True(t, copyToChangedCalled, "CopyToChanged should have been called")

		var data struct {
			UpdateLibraryWidget struct {
				ID     string `json:"id"`
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"updateLibraryWidget"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Equal(t, "changed-widget-123", data.UpdateLibraryWidget.ID)
		assert.Equal(t, "Updated Name", data.UpdateLibraryWidget.Name)
		assert.Equal(t, "CHANGED", data.UpdateLibraryWidget.Status)
	})
}

func TestUpdateLibraryWidget_ChangedDirectUpdate(t *testing.T) {
	t.Run("changed widget updates directly", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:      id,
					GroupID: "group-1",
					Name:    "Changed Widget",
					Status:  model.StatusChanged,
				}, nil
			},
			UpdateLibraryWidgetFunc: func(ctx context.Context, id string, update *repository.LibraryWidgetUpdate) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:     id,
					Name:   *update.Name,
					Status: model.StatusChanged,
				}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(&MockSystemRepository{}, mockWidgetRepo, rbacClient)

		query := `mutation { updateLibraryWidget(input: {id: "widget-changed", name: "Direct Update"}) { id name status } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)

		var data struct {
			UpdateLibraryWidget struct {
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"updateLibraryWidget"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Equal(t, "Direct Update", data.UpdateLibraryWidget.Name)
		assert.Equal(t, "CHANGED", data.UpdateLibraryWidget.Status)
	})
}

func TestUpdateLibraryWidget_TrashedError(t *testing.T) {
	t.Run("trashed widget returns error", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:     id,
					Name:   "Trashed Widget",
					Status: model.StatusTrashed,
				}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(&MockSystemRepository{}, mockWidgetRepo, rbacClient)

		query := `mutation { updateLibraryWidget(input: {id: "widget-trashed", name: "Should Fail"}) { id } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		require.NotEmpty(t, resp.Errors)
		assert.Contains(t, resp.Errors[0].Message, "invalid widget status")
	})
}

func TestPublishLibraryWidget_FromChanged(t *testing.T) {
	t.Run("publishes from changed status with history save", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		saveToHistoryCalled := false
		deletePublishedCalled := false

		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:      id,
					GroupID: "group-1",
					Name:    "Changed Widget",
					Status:  model.StatusChanged,
				}, nil
			},
			GetByGroupAndStatusFunc: func(ctx context.Context, groupID string, status string) (*model.LibraryWidget, error) {
				if status == model.StatusChanged {
					return &model.LibraryWidget{
						ID:      "changed-id",
						GroupID: groupID,
						Status:  model.StatusChanged,
					}, nil
				}
				return nil, nil
			},
			SaveToHistoryFunc: func(ctx context.Context, widgetID string, publishedBy string) error {
				saveToHistoryCalled = true
				assert.Equal(t, "group-1", widgetID)
				return nil
			},
			DeleteByGroupAndStatusFunc: func(ctx context.Context, groupID string, status string) error {
				if status == model.StatusPublished {
					deletePublishedCalled = true
				}
				return nil
			},
			UpdateLibraryWidgetStatusFunc: func(ctx context.Context, id string, status string, previousStatus string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:      id,
					GroupID: "group-1",
					Name:    "Changed Widget",
					Status:  status,
				}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(&MockSystemRepository{}, mockWidgetRepo, rbacClient)

		query := `mutation { publishLibraryWidget(id: "widget-changed") { id status } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)
		assert.True(t, saveToHistoryCalled, "SaveToHistory should have been called")
		assert.True(t, deletePublishedCalled, "DeleteByGroupAndStatus(published) should have been called")

		var data struct {
			PublishLibraryWidget struct {
				Status string `json:"status"`
			} `json:"publishLibraryWidget"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Equal(t, "PUBLISHED", data.PublishLibraryWidget.Status)
	})
}

func TestPublishLibraryWidget_LockedByOther(t *testing.T) {
	t.Run("error when locked by another user", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:      id,
					GroupID: id,
					Name:    "Locked Widget",
					Status:  model.StatusDraft,
				}, nil
			},
		}
		mockLockRepo := &MockLockRepository{
			IsLockedByOtherFunc: func(ctx context.Context, entityType, entityID, userID string) (bool, error) {
				return true, nil // locked by another user
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithServices(&MockSystemRepository{}, mockWidgetRepo, nil, mockLockRepo, rbacClient)

		query := `mutation { publishLibraryWidget(id: "widget-locked") { id } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		require.NotEmpty(t, resp.Errors)
		assert.Contains(t, resp.Errors[0].Message, "locked")
	})
}

func TestRestoreLibraryWidget_WithHistory(t *testing.T) {
	t.Run("restores to published when history exists", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		var restoredStatus string
		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:      id,
					GroupID: id,
					Name:    "Trashed Widget",
					Status:  model.StatusTrashed,
				}, nil
			},
			GetLatestHistoryFunc: func(ctx context.Context, widgetID string) (*model.LibraryWidgetHistory, error) {
				// Has history → was published before
				return &model.LibraryWidgetHistory{
					ID:       "history-1",
					WidgetID: widgetID,
					Version:  1,
				}, nil
			},
			UpdateLibraryWidgetStatusFunc: func(ctx context.Context, id string, status string, previousStatus string) (*model.LibraryWidget, error) {
				restoredStatus = status
				return &model.LibraryWidget{
					ID:     id,
					Name:   "Trashed Widget",
					Status: status,
				}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(&MockSystemRepository{}, mockWidgetRepo, rbacClient)

		query := `mutation { restoreLibraryWidget(id: "widget-trashed") { id status } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)
		assert.Equal(t, model.StatusPublished, restoredStatus)

		var data struct {
			RestoreLibraryWidget struct {
				Status string `json:"status"`
			} `json:"restoreLibraryWidget"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Equal(t, "PUBLISHED", data.RestoreLibraryWidget.Status)
	})
}

func TestRestoreLibraryWidget_WithoutHistory(t *testing.T) {
	t.Run("restores to draft when no history exists", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		var restoredStatus string
		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:      id,
					GroupID: id,
					Name:    "Trashed Draft Widget",
					Status:  model.StatusTrashed,
				}, nil
			},
			GetLatestHistoryFunc: func(ctx context.Context, widgetID string) (*model.LibraryWidgetHistory, error) {
				return nil, nil // No history → never published
			},
			UpdateLibraryWidgetStatusFunc: func(ctx context.Context, id string, status string, previousStatus string) (*model.LibraryWidget, error) {
				restoredStatus = status
				return &model.LibraryWidget{
					ID:     id,
					Name:   "Trashed Draft Widget",
					Status: status,
				}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(&MockSystemRepository{}, mockWidgetRepo, rbacClient)

		query := `mutation { restoreLibraryWidget(id: "widget-trashed") { id status } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)
		assert.Equal(t, model.StatusDraft, restoredStatus)

		var data struct {
			RestoreLibraryWidget struct {
				Status string `json:"status"`
			} `json:"restoreLibraryWidget"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Equal(t, "DRAFT", data.RestoreLibraryWidget.Status)
	})
}

func TestRevertLibraryWidget_Success(t *testing.T) {
	t.Run("reverts published widget to history version", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		saveToHistoryCalled := false
		var updatedName string
		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:      id,
					GroupID: id,
					Name:    "Current Published",
					Status:  model.StatusPublished,
				}, nil
			},
			GetByGroupAndStatusFunc: func(ctx context.Context, groupID string, status string) (*model.LibraryWidget, error) {
				if status == model.StatusPublished {
					return &model.LibraryWidget{
						ID:      groupID,
						GroupID: groupID,
						Name:    "Current Published",
						Status:  model.StatusPublished,
					}, nil
				}
				return nil, nil
			},
			GetHistoryByVersionFunc: func(ctx context.Context, widgetID string, version int) (*model.LibraryWidgetHistory, error) {
				return &model.LibraryWidgetHistory{
					ID:       "history-1",
					WidgetID: widgetID,
					Version:  version,
					Snapshot: model.LibraryWidgetSnapshot{
						Widget: model.LibraryWidget{
							Name:    "Old Version Name",
							Version: "0.9.0",
							Type:    "chart",
						},
					},
				}, nil
			},
			SaveToHistoryFunc: func(ctx context.Context, widgetID string, publishedBy string) error {
				saveToHistoryCalled = true
				return nil
			},
			UpdateLibraryWidgetFunc: func(ctx context.Context, id string, update *repository.LibraryWidgetUpdate) (*model.LibraryWidget, error) {
				updatedName = *update.Name
				return &model.LibraryWidget{
					ID:      id,
					Name:    *update.Name,
					Version: *update.Version,
					Status:  model.StatusPublished,
				}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(&MockSystemRepository{}, mockWidgetRepo, rbacClient)

		query := `mutation { revertLibraryWidget(id: "widget-pub", version: 1) { id name status } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)
		assert.True(t, saveToHistoryCalled, "current published should be saved to history before revert")
		assert.Equal(t, "Old Version Name", updatedName)

		var data struct {
			RevertLibraryWidget struct {
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"revertLibraryWidget"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Equal(t, "Old Version Name", data.RevertLibraryWidget.Name)
		assert.Equal(t, "PUBLISHED", data.RevertLibraryWidget.Status)
	})
}

func TestRevertLibraryWidget_VersionNotFound(t *testing.T) {
	t.Run("error when history version not found", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:      id,
					GroupID: id,
					Status:  model.StatusPublished,
				}, nil
			},
			GetByGroupAndStatusFunc: func(ctx context.Context, groupID string, status string) (*model.LibraryWidget, error) {
				if status == model.StatusPublished {
					return &model.LibraryWidget{ID: groupID, GroupID: groupID, Status: model.StatusPublished}, nil
				}
				return nil, nil
			},
			GetHistoryByVersionFunc: func(ctx context.Context, widgetID string, version int) (*model.LibraryWidgetHistory, error) {
				return nil, nil // version not found
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(&MockSystemRepository{}, mockWidgetRepo, rbacClient)

		query := `mutation { revertLibraryWidget(id: "widget-pub", version: 999) { id } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		require.NotEmpty(t, resp.Errors)
		assert.Contains(t, resp.Errors[0].Message, "history version not found")
	})
}

func TestDiscardLibraryWidget_Success(t *testing.T) {
	t.Run("discards changed version and returns published", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		deleteChangedCalled := false
		callCount := 0
		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:      id,
					GroupID: id,
					Status:  model.StatusPublished,
				}, nil
			},
			GetByGroupAndStatusFunc: func(ctx context.Context, groupID string, status string) (*model.LibraryWidget, error) {
				callCount++
				if status == model.StatusChanged {
					return &model.LibraryWidget{
						ID:      "changed-id",
						GroupID: groupID,
						Status:  model.StatusChanged,
					}, nil
				}
				if status == model.StatusPublished {
					return &model.LibraryWidget{
						ID:      groupID,
						GroupID: groupID,
						Name:    "Published Widget",
						Status:  model.StatusPublished,
					}, nil
				}
				return nil, nil
			},
			DeleteByGroupAndStatusFunc: func(ctx context.Context, groupID string, status string) error {
				if status == model.StatusChanged {
					deleteChangedCalled = true
				}
				return nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(&MockSystemRepository{}, mockWidgetRepo, rbacClient)

		query := `mutation { discardLibraryWidget(id: "widget-pub") { id name status } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)
		assert.True(t, deleteChangedCalled, "changed version should be deleted")

		var data struct {
			DiscardLibraryWidget struct {
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"discardLibraryWidget"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Equal(t, "Published Widget", data.DiscardLibraryWidget.Name)
		assert.Equal(t, "PUBLISHED", data.DiscardLibraryWidget.Status)
	})
}

func TestDiscardLibraryWidget_NoChangedVersion(t *testing.T) {
	t.Run("error when no changed version to discard", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:      id,
					GroupID: id,
					Status:  model.StatusPublished,
				}, nil
			},
			GetByGroupAndStatusFunc: func(ctx context.Context, groupID string, status string) (*model.LibraryWidget, error) {
				return nil, nil // no changed version
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(&MockSystemRepository{}, mockWidgetRepo, rbacClient)

		query := `mutation { discardLibraryWidget(id: "widget-pub") { id } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		require.NotEmpty(t, resp.Errors)
		assert.Contains(t, resp.Errors[0].Message, "no changed version")
	})
}

func TestTrashLibraryWidget_PublishedWithChangedCopy(t *testing.T) {
	t.Run("trashing published also deletes changed copy", func(t *testing.T) {
		rbacServer := CreateMockRBACServer(nil, nil, nil)
		defer rbacServer.Close()

		deleteChangedCalled := false
		mockWidgetRepo := &MockWidgetRepository{
			GetLibraryWidgetFunc: func(ctx context.Context, id string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:      id,
					GroupID: id,
					Name:    "Published Widget",
					Status:  model.StatusPublished,
				}, nil
			},
			GetByGroupAndStatusFunc: func(ctx context.Context, groupID string, status string) (*model.LibraryWidget, error) {
				if status == model.StatusChanged {
					return &model.LibraryWidget{
						ID:      "changed-id",
						GroupID: groupID,
						Status:  model.StatusChanged,
					}, nil
				}
				return nil, nil
			},
			DeleteByGroupAndStatusFunc: func(ctx context.Context, groupID string, status string) error {
				if status == model.StatusChanged {
					deleteChangedCalled = true
				}
				return nil
			},
			UpdateLibraryWidgetStatusFunc: func(ctx context.Context, id string, status string, previousStatus string) (*model.LibraryWidget, error) {
				return &model.LibraryWidget{
					ID:     id,
					Name:   "Published Widget",
					Status: status,
				}, nil
			},
		}

		rbacClient := client.NewRBACClient(rbacServer.URL)
		e := SetupGraphQLWithMocks(&MockSystemRepository{}, mockWidgetRepo, rbacClient)

		query := `mutation { trashLibraryWidget(id: "widget-pub") { id status } }`
		rec := PerformGraphQL(e, query, nil, map[string]string{"x-user-id": "user1"})

		resp, err := ParseGraphQLResponse(rec)
		require.NoError(t, err)
		assert.Empty(t, resp.Errors)
		assert.True(t, deleteChangedCalled, "changed copy should be deleted when trashing published")

		var data struct {
			TrashLibraryWidget struct {
				Status string `json:"status"`
			} `json:"trashLibraryWidget"`
		}
		json.Unmarshal(resp.Data, &data)
		assert.Equal(t, "TRASHED", data.TrashLibraryWidget.Status)
	})
}
