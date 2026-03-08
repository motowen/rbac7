package natshandler

import (
	"fmt"
	"strings"

	natsjwt "github.com/nats-io/jwt/v2"

	"rbac7/internal/rbac/model"
)

// NATSPermissions wraps NATS publish/subscribe permissions.
type NATSPermissions struct {
	Pub natsjwt.Permission
	Sub natsjwt.Permission
}

// MapRolesToNATSPermissions converts RBAC roles to coarse-grained NATS subject permissions.
// This is the "粗粒度" layer of the dual-layer approach:
// - Auth Callout uses this to limit which subjects a user can access
// - Fine-grained RBAC checks still happen inside each NATS handler
func MapRolesToNATSPermissions(roles []*model.UserRole) NATSPermissions {
	perms := NATSPermissions{}

	// All authenticated users can:
	// - Check permissions (public API)
	// - Subscribe to their inbox for request-reply
	perms.Pub.Allow.Add("rbac.permissions.check")
	perms.Pub.Allow.Add("rbac.permissions.check.batch")
	perms.Pub.Allow.Add("rbac.system.get_my_roles")
	perms.Sub.Allow.Add("_INBOX.>")

	if len(roles) == 0 {
		return perms
	}

	// Track which namespaces/resources we've already granted access to
	systemNamespaces := make(map[string]string) // namespace -> highest role
	resourceAccess := make(map[string]bool)     // "resourceType:resourceID" -> granted

	for _, role := range roles {
		if role.DeletedAt != nil {
			continue // Skip soft-deleted roles
		}

		switch role.Scope {
		case model.ScopeSystem:
			ns := strings.ToLower(role.Namespace)
			existing, ok := systemNamespaces[ns]
			if !ok || systemRolePriority(role.Role) > systemRolePriority(existing) {
				systemNamespaces[ns] = role.Role
			}

		case model.ScopeResource:
			key := fmt.Sprintf("%s:%s", role.ResourceType, role.ResourceID)
			if !resourceAccess[key] {
				resourceAccess[key] = true
				// Grant access to all resource operations for this resource
				perms.Pub.Allow.Add("rbac.resource.>")
			}
		}
	}

	// Map system roles to NATS subject permissions
	for ns, role := range systemNamespaces {
		switch role {
		case "moderator":
			// Moderator: full access across all namespaces (can assign owners)
			perms.Pub.Allow.Add("rbac.system.>")
		case "owner", "admin":
			// Owner/Admin: full management within namespace
			perms.Pub.Allow.Add(fmt.Sprintf("rbac.system.%s.>", ns))
			// Also access resource operations under this namespace
			perms.Pub.Allow.Add("rbac.resource.>")
		case "dev_user":
			// Dev user: resource operations (create/read/update/delete/publish) but no member management
			perms.Pub.Allow.Add(fmt.Sprintf("rbac.system.%s.get_members", ns))
			perms.Pub.Allow.Add(fmt.Sprintf("rbac.system.%s.get_logs", ns))
			perms.Pub.Allow.Add("rbac.resource.>")
		case "viewer":
			// Viewer: read-only
			perms.Pub.Allow.Add(fmt.Sprintf("rbac.system.%s.get_members", ns))
			perms.Pub.Allow.Add(fmt.Sprintf("rbac.system.%s.get_logs", ns))
		}
	}

	return perms
}

// systemRolePriority returns the priority of a system role (higher is more privileged).
func systemRolePriority(role string) int {
	switch role {
	case "moderator":
		return 6
	case "owner":
		return 5
	case "admin":
		return 4
	case "dev_user":
		return 2
	case "viewer":
		return 1
	default:
		return 0
	}
}
