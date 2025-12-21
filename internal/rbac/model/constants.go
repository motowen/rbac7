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

	PermResourceDashboardRead          = "resource.dashboard.read"
	PermResourceDashboardUpdate        = "resource.dashboard.update"
	PermResourceDashboardDelete        = "resource.dashboard.delete"
	PermResourceDashboardAddMember     = "resource.dashboard.add_member"
	PermResourceDashboardRemoveMember  = "resource.dashboard.remove_member"
	PermResourceDashboardGetMember     = "resource.dashboard.get_member"
	PermResourceDashboardTransferOwner = "resource.dashboard.transfer_owner"
)

// User Types
const (
	UserTypeMember = "member"
	UserTypeOrg    = "org"
)
