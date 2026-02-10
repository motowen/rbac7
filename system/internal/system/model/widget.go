package model

import "time"

// LibraryWidget represents a library widget template stored in MongoDB
type LibraryWidget struct {
	ID             string                  `bson:"_id,omitempty"`
	Name           string                  `bson:"name"`
	Version        string                  `bson:"version"`
	Type           string                  `bson:"type"`
	TypeVersion    string                  `bson:"type_version"`
	Schema         map[string]interface{}  `bson:"schema,omitempty"`
	Datasource     []Datasource            `bson:"datasource,omitempty"`
	Status         string                  `bson:"status"`
	PreviousStatus string                  `bson:"previous_status,omitempty"`
	DraftData      *LibraryWidgetDraftData `bson:"draft_data,omitempty"`
	ThumbnailURL   string                  `bson:"thumbnail_url,omitempty"`
	DisplayMode    string                  `bson:"display_mode,omitempty"`
	Tags           []string                `bson:"tags,omitempty"`
	CreatedAt      time.Time               `bson:"created_at"`
	UpdatedAt      time.Time               `bson:"updated_at"`
	PublishedAt    *time.Time              `bson:"published_at,omitempty"`
	UserConfig     map[string]interface{}  `bson:"user_config,omitempty"`
}

// LibraryWidgetDraftData stores draft changes when widget is in "changed" status
type LibraryWidgetDraftData struct {
	Name         string                 `bson:"name,omitempty"`
	Version      string                 `bson:"version,omitempty"`
	Schema       map[string]interface{} `bson:"schema,omitempty"`
	Datasource   []Datasource           `bson:"datasource,omitempty"`
	ThumbnailURL string                 `bson:"thumbnail_url,omitempty"`
	DisplayMode  string                 `bson:"display_mode,omitempty"`
	Tags         []string               `bson:"tags,omitempty"`
	UserConfig   map[string]interface{} `bson:"user_config,omitempty"`
}

// DashboardWidget represents a widget instance placed on a dashboard
// Contains fields copied from LibraryWidget + dashboard-specific fields
type DashboardWidget struct {
	ID          string `bson:"_id,omitempty"`
	DashboardID string `bson:"dashboard_id"`
	Version     string `bson:"version"` // "published" | "draft"

	// Fields copied from LibraryWidget
	LibraryWidgetID      string                 `bson:"library_widget_id"`
	LibraryWidgetVersion string                 `bson:"library_widget_version"`
	Type                 string                 `bson:"type"`
	TypeVersion          string                 `bson:"type_version"`
	Name                 string                 `bson:"name"`
	Datasource           []Datasource           `bson:"datasource,omitempty"`
	Schema               map[string]interface{} `bson:"schema,omitempty"`

	// Dashboard Widget specific fields
	DisplayMode     string                 `bson:"display_mode,omitempty"`
	ConfigOverrides map[string]interface{} `bson:"config_overrides"`
	Layout          map[string]interface{} `bson:"layout"`
	QueryOverrides  map[string]interface{} `bson:"query_overrides,omitempty"`
	SortOrder       int                    `bson:"sort_order"`

	CreatedAt time.Time `bson:"created_at"`
	UpdatedAt time.Time `bson:"updated_at"`
}

// Datasource represents widget data source configuration
type Datasource struct {
	ID          string                 `bson:"id"`
	Name        string                 `bson:"name"`
	Description string                 `bson:"description,omitempty"`
	Type        string                 `bson:"type"`
	Config      map[string]interface{} `bson:"config,omitempty"`
}
