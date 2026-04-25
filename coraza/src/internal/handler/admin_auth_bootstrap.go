package handler

import (
	"fmt"
	"os"
	"strings"
	"time"

	"tukuyomi/internal/adminauth"
)

const (
	AdminBootstrapUsernameEnv = "TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME"
	AdminBootstrapEmailEnv    = "TUKUYOMI_ADMIN_BOOTSTRAP_EMAIL"
	AdminBootstrapPasswordEnv = "TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD"
)

func EnsureAdminBootstrapOwnerFromEnv() (bool, error) {
	username := strings.TrimSpace(os.Getenv(AdminBootstrapUsernameEnv))
	password := os.Getenv(AdminBootstrapPasswordEnv)
	email := strings.TrimSpace(os.Getenv(AdminBootstrapEmailEnv))
	if username == "" && strings.TrimSpace(password) == "" && email == "" {
		return false, nil
	}
	if username == "" || strings.TrimSpace(password) == "" {
		return false, fmt.Errorf("%s and %s are required for admin bootstrap", AdminBootstrapUsernameEnv, AdminBootstrapPasswordEnv)
	}

	store := getLogsStatsStore()
	if store == nil {
		return false, errAdminAuthStoreUnavailable
	}
	count, err := store.countAdminUsers()
	if err != nil {
		return false, err
	}
	if count > 0 {
		return false, nil
	}

	passwordHash, err := adminauth.HashPassword(password)
	if err != nil {
		return false, err
	}
	if _, err := store.createAdminUser(username, email, adminauth.AdminRoleOwner, passwordHash, true, time.Now().UTC()); err != nil {
		return false, err
	}
	return true, nil
}

func (s *wafEventStore) countAdminUsers() (int64, error) {
	if s == nil || s.db == nil {
		return 0, errAdminAuthStoreUnavailable
	}
	var count int64
	if err := s.queryRow(`SELECT COUNT(*) FROM admin_users`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}
