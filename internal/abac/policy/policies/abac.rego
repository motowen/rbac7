package abac

import rego.v1

# Default: deny all access
default allow := false

# Default: no deny from group check
default group_denied := false

# Default: no group allow restriction
default group_allow_required := false
default group_allow_passed := false

# =====================
# Step 1: Group Deny List
# =====================
# If subject is in any of the resource's denied groups → deny
group_denied if {
    some g in input.subject.group_ids
    some d in input.resource.denied_group_ids
    g == d
}

# =====================
# Step 2: Group Allow List
# =====================
# If resource has allowed_group_ids, subject must be in at least one
group_allow_required if {
    count(input.resource.allowed_group_ids) > 0
}

group_allow_passed if {
    not group_allow_required
}

group_allow_passed if {
    group_allow_required
    some g in input.subject.group_ids
    some a in input.resource.allowed_group_ids
    g == a
}

# =====================
# Step 3+4: Policy Rule Evaluation
# =====================

# Collect all matching rules with their priority and effect
matching_rules contains rule if {
    some r in input.rules
    r.enabled == true
    r.resource_type == input.resource.resource_type
    r.action == input.action
    all_conditions_met(r.conditions)
    rule := {
        "name": r.name,
        "priority": r.priority,
        "effect": r.effect,
    }
}

# Find the highest priority among matching rules
max_priority := max({r.priority | some r in matching_rules})

# Rules at the highest matched priority level
top_rules contains r if {
    some r in matching_rules
    r.priority == max_priority
}

# Check if any top-priority rule denies
top_deny if {
    some r in top_rules
    r.effect == "deny"
}

# Check if any top-priority rule allows
top_allow if {
    some r in top_rules
    r.effect == "allow"
}

# =====================
# Final Decision
# =====================
allow if {
    not group_denied
    group_allow_passed
    not top_deny
    top_allow
}

# =====================
# Reason output
# =====================
default reason := "no matching policy rules"

reason := "subject is in denied group" if {
    group_denied
}

reason := "subject is not in any allowed group" if {
    not group_denied
    not group_allow_passed
}

deny_rule_names contains r.name if {
    some r in top_rules
    r.effect == "deny"
}

allow_rule_names contains r.name if {
    some r in top_rules
    r.effect == "allow"
}

reason := sprintf("denied by rule: %s", [concat(", ", sort(deny_rule_names))]) if {
    not group_denied
    group_allow_passed
    top_deny
}

reason := sprintf("allowed by rule: %s", [concat(", ", sort(allow_rule_names))]) if {
    not group_denied
    group_allow_passed
    not top_deny
    top_allow
}

# =====================
# Condition Evaluation Helpers
# =====================
all_conditions_met(conditions) if {
    all_subject_conditions_met(conditions)
    all_resource_conditions_met(conditions)
}

# Subject conditions (all must pass)
all_subject_conditions_met(conditions) if {
    not has_subject_conditions(conditions)
}

all_subject_conditions_met(conditions) if {
    has_subject_conditions(conditions)
    every cond in conditions.subject {
        eval_condition(resolve_subject_field(cond.field), cond.operator, cond.value)
    }
}

has_subject_conditions(conditions) if {
    count(conditions.subject) > 0
}

# Resource conditions (all must pass)
all_resource_conditions_met(conditions) if {
    not has_resource_conditions(conditions)
}

all_resource_conditions_met(conditions) if {
    has_resource_conditions(conditions)
    every cond in conditions.resource {
        eval_condition(resolve_resource_field(cond.field), cond.operator, cond.value)
    }
}

has_resource_conditions(conditions) if {
    count(conditions.resource) > 0
}

# =====================
# Field Resolution
# =====================
resolve_subject_field(field) := input.subject.user_id if field == "user_id"
resolve_subject_field(field) := input.subject.role if field == "role"
resolve_subject_field(field) := input.subject.status if field == "status"
resolve_subject_field(field) := input.subject.sensitivity_level if field == "sensitivity_level"
resolve_subject_field(field) := input.subject.group_ids if field == "group_ids"
resolve_subject_field(field) := v if {
    startswith(field, "custom.")
    attr_key := substring(field, 7, -1)
    some attr in input.subject.custom_attrs
    attr.key == attr_key
    v := attr.value
}

resolve_resource_field(field) := input.resource.resource_id if field == "resource_id"
resolve_resource_field(field) := input.resource.resource_type if field == "resource_type"
resolve_resource_field(field) := input.resource.resource_parent_id if field == "resource_parent_id"
resolve_resource_field(field) := input.resource.owner_id if field == "owner_id"
resolve_resource_field(field) := input.resource.sensitivity_level if field == "sensitivity_level"
resolve_resource_field(field) := input.resource.status if field == "status"
resolve_resource_field(field) := input.resource.allowed_group_ids if field == "allowed_group_ids"
resolve_resource_field(field) := input.resource.denied_group_ids if field == "denied_group_ids"
resolve_resource_field(field) := input.resource.resource_group_ids if field == "resource_group_ids"
resolve_resource_field(field) := v if {
    startswith(field, "custom.")
    attr_key := substring(field, 7, -1)
    some attr in input.resource.custom_attrs
    attr.key == attr_key
    v := attr.value
}

# =====================
# Operator Evaluation
# =====================
eval_condition(field_value, op, expected) if {
    op == "eq"
    field_value == expected
}

eval_condition(field_value, op, expected) if {
    op == "neq"
    field_value != expected
}

eval_condition(field_value, op, expected) if {
    op == "in"
    field_value in expected
}

eval_condition(field_value, op, expected) if {
    op == "not_in"
    not field_value in expected
}

eval_condition(field_value, op, expected) if {
    op == "contains"
    expected in field_value
}

eval_condition(field_value, op, expected) if {
    op == "gt"
    field_value > expected
}

eval_condition(field_value, op, expected) if {
    op == "gte"
    field_value >= expected
}

eval_condition(field_value, op, expected) if {
    op == "lt"
    field_value < expected
}

eval_condition(field_value, op, expected) if {
    op == "lte"
    field_value <= expected
}
