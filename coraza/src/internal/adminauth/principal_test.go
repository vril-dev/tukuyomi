package adminauth

import "testing"

func TestPrincipalValidation(t *testing.T) {
	role, ok := ParseAdminRole(" OWNER ")
	if !ok || role != AdminRoleOwner {
		t.Fatalf("parse owner role=%q ok=%v", role, ok)
	}
	if _, ok := ParseAdminRole("root"); ok {
		t.Fatalf("parse invalid role ok=true want false")
	}

	principal := Principal{
		UserID:       1,
		Username:     "admin",
		Role:         AdminRoleOwner,
		AuthKind:     AuthKindSession,
		CredentialID: "1",
	}
	if !principal.Authenticated() {
		t.Fatalf("principal authenticated=false want true")
	}

	principal.Role = "root"
	if principal.Authenticated() {
		t.Fatalf("invalid role principal authenticated=true want false")
	}
}

func TestNormalizeAdminIdentifier(t *testing.T) {
	if got := NormalizeAdminIdentifier(" Admin@Example.COM "); got != "admin@example.com" {
		t.Fatalf("normalized identifier=%q", got)
	}
}
