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

// AllowedSystemRoles defines which roles can be assigned for system scope
var AllowedSystemRoles = map[string]bool{
	RoleSystemAdmin:  true,
	RoleSystemViewer: true,
	RoleSystemDev:    true,
}

// Scopes
const (
	ScopeSystem   = "system"
	ScopeResource = "resource"
)

// Permission constants for strict typing
const (
	PermPlatformSystemCreate        = "platform.system.create"
	PermPlatformSystemRead          = "platform.system.read"
	PermPlatformSystemAddOwner      = "platform.system.add_owner"
	PermPlatformSystemUpdate        = "platform.system.update"
	PermPlatformSystemAddMember     = "platform.system.add_member" // Used for AssignSystemUserRole
	PermPlatformSystemRemoveMember  = "platform.system.remove_member"
	PermPlatformSystemGetMember     = "platform.system.get_member" // Used for GetUserRoles (List)
	PermPlatformSystemTransferOwner = "platform.system.transfer_owner"
	PermSystemResourceCreate        = "system.resource.create"
	PermSystemResourceRead          = "system.resource.read"
	PermSystemResourceDelete        = "system.resource.delete"
	PermSystemResourceUpdate        = "system.resource.update"
	PermSystemResourcePublish       = "system.resource.publish"

	// Resource Scope Permissions (Dashboard)
	PermResourceDashboardRead          = "resource.dashboard.read"
	PermResourceDashboardUpdate        = "resource.dashboard.update"
	PermResourceDashboardDelete        = "resource.dashboard.delete"
	PermResourceDashboardAddMember     = "resource.dashboard.add_member"
	PermResourceDashboardRemoveMember  = "resource.dashboard.remove_member"
	PermResourceDashboardGetMember     = "resource.dashboard.get_member"
	PermResourceDashboardTransferOwner = "resource.dashboard.transfer_owner"

	// Dashboard Widget Permissions
	PermResourceDashboardAddWidget       = "resource.dashboard.add_widget"
	PermResourceDashboardRemoveWidget    = "resource.dashboard.remove_widget"
	PermResourceDashboardAddWidgetViewer = "resource.dashboard.add_widget_viewer"
	PermResourceDashboardWidgetRead      = "resource.dashboard_widget.read"
	PermResourceDashboardWidgetGetMember = "resource.dashboard_widget.get_member"

	// Library Widget Permissions
	PermResourceLibraryWidgetRead      = "resource.library_widget.read"
	PermResourceLibraryWidgetGetMember = "resource.library_widget.get_member"
)

// User Types
const (
	UserTypeMember = "member"
	UserTypeOrg    = "org"
)

// Resource Types
const (
	ResourceTypeDashboard     = "dashboard"
	ResourceTypeWidget        = "dashboard_widget"
	ResourceTypeLibraryWidget = "library_widget"
)
