package model

import "time"

// LibraryWidgetHistory stores published snapshots for rollback
type LibraryWidgetHistory struct {
	ID          string                `bson:"_id,omitempty"`
	WidgetID    string                `bson:"widget_id"`
	Version     int                   `bson:"version"`
	Snapshot    LibraryWidgetSnapshot `bson:"snapshot"`
	PublishedAt time.Time             `bson:"published_at"`
	PublishedBy string                `bson:"published_by"`
}

// LibraryWidgetSnapshot contains a complete snapshot of the library widget
type LibraryWidgetSnapshot struct {
	Widget LibraryWidget `bson:"widget"`
}
