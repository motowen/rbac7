package model

// Effect determines the outcome of a policy rule match
const (
	EffectAllow = "allow"
	EffectDeny  = "deny"
)

// Operators for condition evaluation
const (
	OpEq       = "eq"
	OpNeq      = "neq"
	OpIn       = "in"
	OpNotIn    = "not_in"
	OpGt       = "gt"
	OpGte      = "gte"
	OpLt       = "lt"
	OpLte      = "lte"
	OpContains = "contains"
)

// ValidOperators is the set of supported operators
var ValidOperators = map[string]bool{
	OpEq: true, OpNeq: true,
	OpIn: true, OpNotIn: true,
	OpGt: true, OpGte: true,
	OpLt: true, OpLte: true,
	OpContains: true,
}

// Attribute scope
const (
	ScopeSubject  = "subject"
	ScopeResource = "resource"
)

// Attribute types for AttributeDefinition
const (
	AttrTypeString = "string"
	AttrTypeNumber = "number"
	AttrTypeEnum   = "enum"
	AttrTypeBool   = "bool"
)

// Subject status
const (
	StatusActive   = "active"
	StatusInactive = "inactive"
	StatusSuspended = "suspended"
)
