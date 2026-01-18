package repository

import (
	"context"
	"rbac7/internal/rbac/model"
	"time"
)

// HistoryRepository defines the interface for user role history operations
type HistoryRepository interface {
	// CreateHistory creates a new history record (append-only)
	CreateHistory(ctx context.Context, history *model.UserRoleHistory) error
	// FindHistory finds history records with pagination and filtering
	FindHistory(ctx context.Context, req model.GetUserRoleHistoryReq) ([]*model.UserRoleHistory, int64, error)
	// EnsureHistoryIndexes creates indexes for efficient querying
	EnsureHistoryIndexes(ctx context.Context) error
}

// HistoryEntry is a helper struct for creating history records
type HistoryEntry struct {
	Operation        string
	CallerID         string
	Scope            string
	Namespace        string
	ResourceID       string
	ResourceType     string
	ParentResourceID string
	UserID           string
	UserIDs          []string
	UserType         string
	Role             string
	NewOwnerID       string
	ChildResourceIDs []string
}

// ToUserRoleHistory converts HistoryEntry to UserRoleHistory with timestamp
func (e *HistoryEntry) ToUserRoleHistory() *model.UserRoleHistory {
	return &model.UserRoleHistory{
		Operation:        e.Operation,
		CallerID:         e.CallerID,
		Scope:            e.Scope,
		Namespace:        e.Namespace,
		ResourceID:       e.ResourceID,
		ResourceType:     e.ResourceType,
		ParentResourceID: e.ParentResourceID,
		UserID:           e.UserID,
		UserIDs:          e.UserIDs,
		UserType:         e.UserType,
		Role:             e.Role,
		NewOwnerID:       e.NewOwnerID,
		ChildResourceIDs: e.ChildResourceIDs,
		CreatedAt:        time.Now(),
	}
}
