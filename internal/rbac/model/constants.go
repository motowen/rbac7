package model

// Roles
const (
	RoleSystemModerator = "moderator"
	RoleSystemOwner     = "owner"
	RoleSystemAdmin     = "admin"
	RoleSystemDev       = "dev_user"
	RoleSystemViewer    = "viewer"

	RoleResourceOwner  = "owner"
	RoleResourceAdmin  = "admin"
	RoleResourceEditor = "editor"
	RoleResourceViewer = "viewer"
)

// Scopes
const (
	ScopeSystem   = "system"
	ScopeResource = "resource"
)

// Permissions
const (
	PermSystemUpdate        = "platform.system.update"
	PermSystemRead          = "platform.system.read"
	PermSystemAddMember     = "platform.system.add_member"
	PermSystemRemoveMember  = "platform.system.remove_member"
	PermSystemGetMember     = "platform.system.get_member"
	PermSystemAddOwner      = "platform.system.add_owner"
	PermSystemTransferOwner = "platform.system.transfer_owner"

	PermSystemResourceCreate = "system.resource.create"
	PermSystemResourceRead   = "system.resource.read"
)

// User Types
const (
	UserTypeMember = "member"
	UserTypeOrg    = "org"
)
