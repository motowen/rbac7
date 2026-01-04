package policy

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

//go:embed policies.json
var defaultPolicies []byte

// Condition defines matchers for context variables
type Condition map[string]interface{}

// Rule defines a single permission rule
type Rule struct {
	Conditions Condition `json:"conditions,omitempty"`
	Permission string    `json:"permission"`      // supports {placeholders}
	Scope      string    `json:"scope,omitempty"` // e.g., "parent", "resource" (default)
}

// PolicyConfig maps actions to lists of rules
type PolicyConfig map[string][]Rule

// PolicyEngine handles permission resolution
type PolicyEngine struct {
	policies PolicyConfig
}

// NewPolicyEngine creates a new engine with default policies
func NewPolicyEngine() *PolicyEngine {
	e := &PolicyEngine{
		policies: make(PolicyConfig),
	}
	// Load default embedded policies
	if len(defaultPolicies) > 0 {
		_ = json.Unmarshal(defaultPolicies, &e.policies)
	}
	return e
}

// LoadPoliciesFromFile loads rules from a JSON file
func (e *PolicyEngine) LoadPoliciesFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &e.policies)
}

// LoadPoliciesFromString loads rules from a JSON string (for testing)
func (e *PolicyEngine) LoadPoliciesFromString(data string) error {
	return json.Unmarshal([]byte(data), &e.policies)
}

// GetPermission resolves the required permission and scope for an action given a context
func (e *PolicyEngine) GetPermission(action string, ctx map[string]interface{}) (perm string, scope string, err error) {
	rules, ok := e.policies[action]
	if !ok {
		return "", "", fmt.Errorf("no policies defined for action: %s", action)
	}

	for _, rule := range rules {
		if e.matches(rule.Conditions, ctx) {
			// Rule matched
			perm = rule.Permission
			scope = rule.Scope
			if scope == "" {
				scope = "resource" // default
			}

			// Replace placeholders in permission string
			// e.g. "resource.{resource_type}.add_member" -> "resource.dashboard.add_member"
			perm = e.interpolate(perm, ctx)
			return perm, scope, nil
		}
	}

	return "", "", fmt.Errorf("no matching rule found for action: %s", action)
}

func (e *PolicyEngine) matches(conditions Condition, ctx map[string]interface{}) bool {
	if len(conditions) == 0 {
		return true // No conditions = always match (default rule)
	}
	for key, expectedVal := range conditions {
		actualVal, ok := ctx[key]
		if !ok {
			return false // Context missing required key
		}
		if actualVal != expectedVal {
			return false // Value mismatch
		}
	}
	return true
}

func (e *PolicyEngine) interpolate(s string, ctx map[string]interface{}) string {
	for k, v := range ctx {
		placeholder := "{" + k + "}"
		if strings.Contains(s, placeholder) {
			valStr := fmt.Sprintf("%v", v)
			s = strings.ReplaceAll(s, placeholder, valStr)
		}
	}
	return s
}
