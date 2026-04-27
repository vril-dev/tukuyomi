package adminauth

import "strings"

type AdminRole string

const (
	AdminRoleOwner    AdminRole = "owner"
	AdminRoleOperator AdminRole = "operator"
	AdminRoleViewer   AdminRole = "viewer"
)

type AuthKind string

const (
	AuthKindSession AuthKind = "session"
	AuthKindToken   AuthKind = "token"
	AuthKindLegacy  AuthKind = "legacy_key"
)

type Principal struct {
	UserID             int64
	Username           string
	Role               AdminRole
	AuthKind           AuthKind
	CredentialID       string
	Scopes             []string
	MustChangePassword bool
}

func NormalizeAdminIdentifier(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func ParseAdminRole(role string) (AdminRole, bool) {
	switch AdminRole(strings.ToLower(strings.TrimSpace(role))) {
	case AdminRoleOwner:
		return AdminRoleOwner, true
	case AdminRoleOperator:
		return AdminRoleOperator, true
	case AdminRoleViewer:
		return AdminRoleViewer, true
	default:
		return "", false
	}
}

func (p Principal) Authenticated() bool {
	return p.UserID > 0 && p.Username != "" && p.Role.Valid() && p.AuthKind.Valid()
}

func (r AdminRole) Valid() bool {
	switch r {
	case AdminRoleOwner, AdminRoleOperator, AdminRoleViewer:
		return true
	default:
		return false
	}
}

func (k AuthKind) Valid() bool {
	switch k {
	case AuthKindSession, AuthKindToken, AuthKindLegacy:
		return true
	default:
		return false
	}
}
