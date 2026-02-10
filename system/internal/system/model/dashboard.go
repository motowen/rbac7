package model

import "time"

// Dashboard represents a dashboard stored in MongoDB
type Dashboard struct {
	ID             string              `bson:"_id,omitempty"`
	Name           string              `bson:"name"`
	Description    string              `bson:"description,omitempty"`
	Status         string              `bson:"status"` // draft|published|changed|trashed
	DraftData      *DashboardDraftData `bson:"draft_data,omitempty"`
	PreviousStatus string              `bson:"previous_status,omitempty"` // for restore
	CreatedAt      time.Time           `bson:"created_at"`
	UpdatedAt      time.Time           `bson:"updated_at"`
	CreatedBy      string              `bson:"created_by"`
}

// DashboardDraftData stores draft changes when dashboard is in "changed" status
type DashboardDraftData struct {
	Name        string `bson:"name,omitempty"`
	Description string `bson:"description,omitempty"`
}

// DashboardHistory stores published snapshots for rollback
type DashboardHistory struct {
	ID          string            `bson:"_id,omitempty"`
	DashboardID string            `bson:"dashboard_id"`
	Version     int               `bson:"version"`
	Snapshot    DashboardSnapshot `bson:"snapshot"`
	PublishedAt time.Time         `bson:"published_at"`
	PublishedBy string            `bson:"published_by"`
}

// DashboardSnapshot contains a complete snapshot of dashboard and widgets
type DashboardSnapshot struct {
	Dashboard Dashboard         `bson:"dashboard"`
	Widgets   []DashboardWidget `bson:"widgets"`
}
