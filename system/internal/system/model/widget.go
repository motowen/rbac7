package model

import "time"

// LibraryWidget represents a library widget template stored in MongoDB
type LibraryWidget struct {
	ID           string                 `bson:"_id,omitempty"`
	Name         string                 `bson:"name"`
	Version      string                 `bson:"version"`
	Type         string                 `bson:"type"`
	TypeVersion  string                 `bson:"type_version"`
	Schema       map[string]interface{} `bson:"schema,omitempty"`
	Datasource   []Datasource           `bson:"datasource,omitempty"`
	Status       string                 `bson:"status"`
	ThumbnailURL string                 `bson:"thumbnail_url,omitempty"`
	CreatedAt    time.Time              `bson:"created_at"`
	UpdatedAt    time.Time              `bson:"updated_at"`
	PublishedAt  *time.Time             `bson:"published_at,omitempty"`
	UserConfig   map[string]interface{} `bson:"user_config,omitempty"`
}

// DashboardWidget represents a widget instance placed on a dashboard
type DashboardWidget struct {
	ID              string                `bson:"_id,omitempty"`
	DashboardID     string                `bson:"dashboard_id"`
	LibraryWidgetID string                `bson:"library_widget_id"`
	Layout          DashboardWidgetLayout `bson:"layout"`
	CreatedAt       time.Time             `bson:"created_at"`
	UpdatedAt       time.Time             `bson:"updated_at"`
}

// Datasource represents widget data source configuration
type Datasource struct {
	ID          string                 `bson:"id"`
	Name        string                 `bson:"name"`
	Description string                 `bson:"description,omitempty"`
	Type        string                 `bson:"type"`
	Config      map[string]interface{} `bson:"config,omitempty"`
}

// DashboardWidgetLayout represents layout for dashboard widget
type DashboardWidgetLayout struct {
	X int `bson:"x"`
	Y int `bson:"y"`
	W int `bson:"w"`
	H int `bson:"h"`
}
