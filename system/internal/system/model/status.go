package model

import "fmt"

// Shared status constants for entities with a status state machine
const (
	StatusDraft     = "draft"
	StatusPublished = "published"
	StatusChanged   = "changed"
	StatusTrashed   = "trashed"
)

// validTransitions defines the allowed status transitions
var validTransitions = map[string][]string{
	StatusDraft:     {StatusPublished, StatusTrashed},
	StatusPublished: {StatusChanged, StatusTrashed},
	StatusChanged:   {StatusPublished, StatusTrashed},
	// StatusTrashed → restored to previous_status (handled separately)
}

// ValidateStatusTransition checks if transitioning from → to is allowed
func ValidateStatusTransition(from, to string) error {
	// Trashed can be restored to any valid status (via previous_status)
	if from == StatusTrashed {
		if to == StatusDraft || to == StatusPublished || to == StatusChanged {
			return nil
		}
		return fmt.Errorf("invalid restore target status: %s", to)
	}

	allowed, ok := validTransitions[from]
	if !ok {
		return fmt.Errorf("unknown current status: %s", from)
	}

	for _, s := range allowed {
		if s == to {
			return nil
		}
	}

	return fmt.Errorf("invalid status transition: %s → %s", from, to)
}

// IsEditable returns true if the status allows editing (draft or changed)
func IsEditable(status string) bool {
	return status == StatusDraft || status == StatusChanged
}
