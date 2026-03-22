package policy

import (
	"context"
	"fmt"
	"rbac7/internal/abac/model"
	"rbac7/internal/abac/repository"
	"sort"
	"strings"
)

// Engine is the ABAC policy engine for access control evaluation
type Engine struct {
	policyRepo repository.PolicyRepository
}

// NewEngine creates a new ABAC Policy Engine
func NewEngine(policyRepo repository.PolicyRepository) *Engine {
	return &Engine{
		policyRepo: policyRepo,
	}
}

// CheckAccess evaluates whether a subject can perform an action on a resource
// Logic:
// 1. Check group deny list (denied_group_ids) — immediate deny
// 2. Check group allow list (allowed_group_ids) — if present, require intersection
// 3. Load applicable policy rules (by resource_type + action, enabled, sorted by priority desc)
// 4. Evaluate rules: same priority → deny wins; different priority → highest priority wins
// 5. No matching rule → default deny
func (e *Engine) CheckAccess(
	ctx context.Context,
	subject *model.Subject,
	resource *model.ResourceAttrs,
	action string,
) (*model.CheckAccessResponse, error) {
	// Step 1: Check denied_group_ids — if subject is in any denied group, immediate deny
	if len(resource.DeniedGroupIDs) > 0 && len(subject.GroupIDs) > 0 {
		if hasIntersection(subject.GroupIDs, resource.DeniedGroupIDs) {
			return &model.CheckAccessResponse{
				Allowed: false,
				Reason:  "subject is in denied group",
			}, nil
		}
	}

	// Step 2: Check allowed_group_ids — if present, subject must be in at least one allowed group
	if len(resource.AllowedGroupIDs) > 0 {
		if len(subject.GroupIDs) == 0 || !hasIntersection(subject.GroupIDs, resource.AllowedGroupIDs) {
			return &model.CheckAccessResponse{
				Allowed: false,
				Reason:  "subject is not in any allowed group",
			}, nil
		}
	}

	// Step 3: Load applicable policy rules
	rules, err := e.policyRepo.FindPolicyRules(ctx, resource.ResourceType, action)
	if err != nil {
		return nil, fmt.Errorf("failed to load policy rules: %w", err)
	}

	if len(rules) == 0 {
		// No rules defined → default deny
		return &model.CheckAccessResponse{
			Allowed: false,
			Reason:  "no matching policy rules",
		}, nil
	}

	// Step 4: Evaluate rules (already sorted by priority desc from repo)
	return e.evaluateRules(subject, resource, rules), nil
}

// evaluateRules processes rules sorted by priority (desc).
// Within the same priority level, deny takes precedence.
// The first priority level that has any matching rule determines the result.
func (e *Engine) evaluateRules(subject *model.Subject, resource *model.ResourceAttrs, rules []*model.PolicyRule) *model.CheckAccessResponse {
	// Group rules by priority
	type priorityGroup struct {
		priority int
		rules    []*model.PolicyRule
	}

	groups := make([]priorityGroup, 0)
	var currentGroup *priorityGroup

	for _, rule := range rules {
		if currentGroup == nil || currentGroup.priority != rule.Priority {
			groups = append(groups, priorityGroup{priority: rule.Priority})
			currentGroup = &groups[len(groups)-1]
		}
		currentGroup.rules = append(currentGroup.rules, rule)
	}

	// Evaluate each priority group (highest first)
	for _, group := range groups {
		var matchedAllow *model.PolicyRule
		var matchedDeny *model.PolicyRule

		for _, rule := range group.rules {
			if e.evaluateConditions(subject, resource, &rule.Conditions) {
				if rule.Effect == model.EffectDeny {
					matchedDeny = rule
				} else if rule.Effect == model.EffectAllow && matchedAllow == nil {
					matchedAllow = rule
				}
			}
		}

		// If any rule matched at this priority level, decide
		if matchedDeny != nil {
			return &model.CheckAccessResponse{
				Allowed: false,
				Reason:  fmt.Sprintf("denied by rule: %s", matchedDeny.Name),
			}
		}
		if matchedAllow != nil {
			return &model.CheckAccessResponse{
				Allowed: true,
				Reason:  fmt.Sprintf("allowed by rule: %s", matchedAllow.Name),
			}
		}
	}

	// No matching rules → default deny
	return &model.CheckAccessResponse{
		Allowed: false,
		Reason:  "no matching policy rules",
	}
}

// evaluateConditions checks if both subject and resource conditions are satisfied
func (e *Engine) evaluateConditions(subject *model.Subject, resource *model.ResourceAttrs, conditions *model.ConditionSet) bool {
	// All subject conditions must pass (AND logic)
	for _, cond := range conditions.Subject {
		fieldValue := resolveSubjectField(subject, cond.Field)
		if !EvaluateCondition(fieldValue, cond.Operator, cond.Value) {
			return false
		}
	}

	// All resource conditions must pass (AND logic)
	for _, cond := range conditions.Resource {
		fieldValue := resolveResourceField(resource, cond.Field)
		if !EvaluateCondition(fieldValue, cond.Operator, cond.Value) {
			return false
		}
	}

	return true
}

// EvaluateCondition evaluates a single condition: fieldValue <operator> expectedValue
func EvaluateCondition(fieldValue interface{}, operator string, expectedValue interface{}) bool {
	switch operator {
	case model.OpEq:
		return compareEqual(fieldValue, expectedValue)
	case model.OpNeq:
		return !compareEqual(fieldValue, expectedValue)
	case model.OpIn:
		return valueIn(fieldValue, expectedValue)
	case model.OpNotIn:
		return !valueIn(fieldValue, expectedValue)
	case model.OpContains:
		return sliceContains(fieldValue, expectedValue)
	case model.OpGt:
		return compareNumeric(fieldValue, expectedValue) > 0
	case model.OpGte:
		return compareNumeric(fieldValue, expectedValue) >= 0
	case model.OpLt:
		return compareNumeric(fieldValue, expectedValue) < 0
	case model.OpLte:
		return compareNumeric(fieldValue, expectedValue) <= 0
	default:
		return false
	}
}

// resolveSubjectField extracts a field value from the Subject
func resolveSubjectField(subject *model.Subject, field string) interface{} {
	switch field {
	case "user_id":
		return subject.UserID
	case "role":
		return subject.Role
	case "status":
		return subject.Status
	case "sensitivity_level":
		return subject.SensitivityLevel
	case "group_ids":
		return subject.GroupIDs
	default:
		// Check custom attributes (e.g. "custom.team")
		if strings.HasPrefix(field, "custom.") {
			attrKey := strings.TrimPrefix(field, "custom.")
			for _, attr := range subject.CustomAttrs {
				if attr.Key == attrKey {
					return attr.Value
				}
			}
		}
		return nil
	}
}

// resolveResourceField extracts a field value from the ResourceAttrs
func resolveResourceField(resource *model.ResourceAttrs, field string) interface{} {
	switch field {
	case "resource_id":
		return resource.ResourceID
	case "resource_type":
		return resource.ResourceType
	case "resource_parent_id":
		return resource.ResourceParentID
	case "owner_id":
		return resource.OwnerID
	case "sensitivity_level":
		return resource.SensitivityLevel
	case "status":
		return resource.Status
	case "allowed_group_ids":
		return resource.AllowedGroupIDs
	case "denied_group_ids":
		return resource.DeniedGroupIDs
	case "resource_group_ids":
		return resource.ResourceGroupIDs
	default:
		// Check custom attributes (e.g. "custom.doc.sensitivity")
		if strings.HasPrefix(field, "custom.") {
			attrKey := strings.TrimPrefix(field, "custom.")
			for _, attr := range resource.CustomAttrs {
				if attr.Key == attrKey {
					return attr.Value
				}
			}
		}
		return nil
	}
}

// --- Helper functions ---

// hasIntersection checks if two string slices have any common element
func hasIntersection(a, b []string) bool {
	set := make(map[string]bool, len(b))
	for _, v := range b {
		set[v] = true
	}
	for _, v := range a {
		if set[v] {
			return true
		}
	}
	return false
}

// compareEqual compares two values for equality (handles type conversion)
func compareEqual(a, b interface{}) bool {
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// valueIn checks if value is in a list (expectedValue should be a slice)
func valueIn(fieldValue, expectedValue interface{}) bool {
	list := toStringSlice(expectedValue)
	fieldStr := fmt.Sprintf("%v", fieldValue)
	for _, item := range list {
		if item == fieldStr {
			return true
		}
	}
	return false
}

// sliceContains checks if a slice field contains the expected value
func sliceContains(fieldValue, expectedValue interface{}) bool {
	list := toStringSlice(fieldValue)
	expected := fmt.Sprintf("%v", expectedValue)
	for _, item := range list {
		if item == expected {
			return true
		}
	}
	return false
}

// compareNumeric compares two values as float64, returns -1, 0, 1
func compareNumeric(a, b interface{}) int {
	fa := toFloat64(a)
	fb := toFloat64(b)
	if fa < fb {
		return -1
	}
	if fa > fb {
		return 1
	}
	return 0
}

// toFloat64 attempts to convert a value to float64
func toFloat64(v interface{}) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case float32:
		return float64(val)
	case int:
		return float64(val)
	case int32:
		return float64(val)
	case int64:
		return float64(val)
	case string:
		var f float64
		fmt.Sscanf(val, "%f", &f)
		return f
	default:
		return 0
	}
}

// toStringSlice converts an interface to a string slice
func toStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case []string:
		return val
	case []interface{}:
		result := make([]string, len(val))
		for i, item := range val {
			result[i] = fmt.Sprintf("%v", item)
		}
		return result
	default:
		return nil
	}
}

// SortRulesByPriority sorts rules by priority descending
func SortRulesByPriority(rules []*model.PolicyRule) {
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority > rules[j].Priority
	})
}
