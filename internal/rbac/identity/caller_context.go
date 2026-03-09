package identity

import "time"

// CallerContext carries trusted caller identity derived from verified credentials.
type CallerContext struct {
	UserID       string
	UserType     string
	ActiveTenant string
	OrgIDs       []string
	Subject      string
	Audience     []string
	ExpiresAt    time.Time
	RawClaims    map[string]any
}
