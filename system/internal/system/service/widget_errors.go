package service

import "errors"

// Widget service errors
var (
	ErrWidgetNotFound         = errors.New("library widget not found")
	ErrInvalidWidgetStatus    = errors.New("invalid widget status for this operation")
	ErrNoChangedVersion       = errors.New("no changed version found")
	ErrNoPublishedVersion     = errors.New("no published version found")
	ErrHistoryVersionNotFound = errors.New("history version not found")
)
