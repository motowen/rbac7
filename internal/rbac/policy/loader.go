package policy

import (
	"embed"
	"encoding/json"
	"fmt"
	"path/filepath"
)

//go:embed policies/operations/*.json policies/check_permission.json
var policiesFS embed.FS

// Loader loads policy configurations from embedded JSON files
type Loader struct{}

func NewLoader() *Loader {
	return &Loader{}
}

// LoadEntityPolicies loads all entity operation policies
func (l *Loader) LoadEntityPolicies() (map[string]*EntityPolicy, error) {
	policies := make(map[string]*EntityPolicy)

	entries, err := policiesFS.ReadDir("policies/operations")
	if err != nil {
		return nil, fmt.Errorf("failed to read policies directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		data, err := policiesFS.ReadFile("policies/operations/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to read policy file %s: %w", entry.Name(), err)
		}

		var policy EntityPolicy
		if err := json.Unmarshal(data, &policy); err != nil {
			return nil, fmt.Errorf("failed to parse policy file %s: %w", entry.Name(), err)
		}

		policies[policy.Entity] = &policy
	}

	return policies, nil
}

// LoadCheckPermissionConfig loads the check permission configuration
func (l *Loader) LoadCheckPermissionConfig() (*CheckPermissionConfig, error) {
	data, err := policiesFS.ReadFile("policies/check_permission.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read check_permission.json: %w", err)
	}

	var config CheckPermissionConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse check_permission.json: %w", err)
	}

	return &config, nil
}
