package nats

import "rbac7/internal/rbac/config"

func publishGrants() []string {
	return []string{"_INBOX.>"}
}

func subscribeGrants(cfg config.NATSConfig) []string {
	grants := []string{SubjectCheck, SubjectCheckBatch, SubjectRolesMe}
	for _, prefix := range cfg.AppRequestSubjectPrefixes {
		if prefix != "" {
			grants = append(grants, prefix)
		}
	}
	return grants
}
