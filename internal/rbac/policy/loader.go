package policy

import (
	"embed"
	"encoding/json"
	"fmt"
	"path/filepath"
)

//go:embed policies/operations/*.json policies/check_permission.json policies/roles/*.json
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

// LoadSystemRolePermissions loads system role permissions from JSON
func (l *Loader) LoadSystemRolePermissions() (map[string][]string, error) {
	data, err := policiesFS.ReadFile("policies/roles/system_roles.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read system_roles.json: %w", err)
	}

	var perms map[string][]string
	if err := json.Unmarshal(data, &perms); err != nil {
		return nil, fmt.Errorf("failed to parse system_roles.json: %w", err)
	}

	return perms, nil
}

// LoadResourceRolePermissions loads resource role permissions from JSON
func (l *Loader) LoadResourceRolePermissions() (map[string][]string, error) {
	data, err := policiesFS.ReadFile("policies/roles/resource_roles.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read resource_roles.json: %w", err)
	}

	var perms map[string][]string
	if err := json.Unmarshal(data, &perms); err != nil {
		return nil, fmt.Errorf("failed to parse resource_roles.json: %w", err)
	}

	return perms, nil
}

// LoadAPIConfigs builds an index of API configurations for middleware matching
// Returns a map where key is "METHOD:PATH" (e.g., "POST:/api/v1/user_roles")
// and value is a list of APIConfigs (multiple configs for same path with different conditions)
func (l *Loader) LoadAPIConfigs(entityPolicies map[string]*EntityPolicy) map[string][]*APIConfig {
	apiConfigs := make(map[string][]*APIConfig)

	for _, entityPolicy := range entityPolicies {
		for opName, opPolicy := range entityPolicy.Operations {
			// Skip operations without API routing info
			if opPolicy.Method == "" || opPolicy.Path == "" {
				continue
			}

			key := opPolicy.Method + ":" + opPolicy.Path
			config := &APIConfig{
				Entity:    entityPolicy.Entity,
				Operation: opName,
				Policy:    opPolicy,
			}

			apiConfigs[key] = append(apiConfigs[key], config)
		}
	}

	return apiConfigs
}
