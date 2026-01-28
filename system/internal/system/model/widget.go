package model

import "time"

// LibraryWidget represents a library widget template stored in MongoDB
type LibraryWidget struct {
	ID         string              `bson:"_id,omitempty"`
	Type       string              `bson:"type"`
	Metadata   WidgetMetadata      `bson:"metadata"`
	Datasource *Datasource         `bson:"datasource,omitempty"`
	Props      *WidgetProps        `bson:"props,omitempty"`
	Slots      *SlotsConfig        `bson:"slots,omitempty"`
	Layout     LibraryWidgetLayout `bson:"layout"`
	Status     string              `bson:"status"`
	CreatedAt  time.Time           `bson:"created_at"`
	UpdatedAt  time.Time           `bson:"updated_at"`
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

// WidgetMetadata represents widget metadata
type WidgetMetadata struct {
	Name        string `bson:"name"`
	Description string `bson:"description,omitempty"`
}

// Datasource represents widget data source configuration
type Datasource struct {
	ID           string     `bson:"id"`
	Name         string     `bson:"name"`
	Type         string     `bson:"type"`
	Trigger      string     `bson:"trigger"`
	DatasourceID string     `bson:"datasource_id"`
	Transform    string     `bson:"transform,omitempty"`
	ParamMap     []ParamMap `bson:"param_map,omitempty"`
}

// ParamMap represents a key-value parameter mapping
type ParamMap struct {
	Key   string `bson:"key"`
	Value string `bson:"value"`
}

// WidgetProps represents widget properties
type WidgetProps struct {
	Title       string        `bson:"title,omitempty"`
	Description string        `bson:"description,omitempty"`
	Fields      []FieldConfig `bson:"fields,omitempty"`
	Options     *PropsOptions `bson:"options,omitempty"`
}

// FieldConfig represents a field configuration
type FieldConfig struct {
	Key   string `bson:"key"`
	Label string `bson:"label"`
	Type  string `bson:"type"`
	Width int    `bson:"width,omitempty"`
}

// PropsOptions represents widget options
type PropsOptions struct {
	EnablePagination bool `bson:"enable_pagination,omitempty"`
	PageSize         int  `bson:"page_size,omitempty"`
	EnableSorting    bool `bson:"enable_sorting,omitempty"`
}

// SlotsConfig represents slots configuration
type SlotsConfig struct {
	Config string `bson:"config,omitempty"`
}

// LibraryWidgetLayout represents layout for library widget
type LibraryWidgetLayout struct {
	X    int `bson:"x"`
	Y    int `bson:"y"`
	W    int `bson:"w"`
	H    int `bson:"h"`
	MinW int `bson:"min_w,omitempty"`
	MinH int `bson:"min_h,omitempty"`
}

// DashboardWidgetLayout represents layout for dashboard widget
type DashboardWidgetLayout struct {
	X int `bson:"x"`
	Y int `bson:"y"`
	W int `bson:"w"`
	H int `bson:"h"`
}
