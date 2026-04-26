package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"tukuyomi/internal/adminauth"
)

const (
	startupAdminUsersSeedName = "admin-users.json"
	maxAdminUserSeedRecords   = 16
)

type adminUserSeedFile struct {
	Users []adminUserSeedRecord `json:"users"`
}

type adminUserSeedRecord struct {
	Username           string `json:"username"`
	Email              string `json:"email"`
	Role               string `json:"role"`
	Password           string `json:"password"`
	MustChangePassword *bool  `json:"must_change_password"`
}

type preparedAdminUserSeedRecord struct {
	Username           string
	Email              string
	Role               adminauth.AdminRole
	Password           string
	MustChangePassword bool
}

func importAdminUsersSeedStorage() error {
	raw, found, err := readStartupSeedFile("", startupAdminUsersSeedName)
	if err != nil {
		return fmt.Errorf("read admin users seed file: %w", err)
	}
	if !found || strings.TrimSpace(string(raw)) == "" {
		return nil
	}
	prepared, err := prepareAdminUsersSeed(raw)
	if err != nil {
		return fmt.Errorf("validate admin users seed file: %w", err)
	}
	if len(prepared) == 0 {
		return nil
	}

	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}
	count, err := store.countAdminUsers()
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	now := time.Now().UTC()
	for _, user := range prepared {
		passwordHash, err := adminauth.HashPassword(user.Password)
		if err != nil {
			return err
		}
		if _, err := store.createAdminUser(user.Username, user.Email, user.Role, passwordHash, user.MustChangePassword, now); err != nil {
			return err
		}
	}
	return nil
}

func prepareAdminUsersSeed(raw []byte) ([]preparedAdminUserSeedRecord, error) {
	var payload adminUserSeedFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("admin users seed must contain a single JSON object")
	}
	if len(payload.Users) > maxAdminUserSeedRecords {
		return nil, fmt.Errorf("too many admin user seed records")
	}

	seenUsernames := map[string]struct{}{}
	seenEmails := map[string]struct{}{}
	prepared := make([]preparedAdminUserSeedRecord, 0, len(payload.Users))
	for index, seed := range payload.Users {
		username, usernameNormalized, err := normalizeAdminUsername(seed.Username)
		if err != nil {
			return nil, fmt.Errorf("users[%d].username: %w", index, err)
		}
		if _, ok := seenUsernames[usernameNormalized]; ok {
			return nil, fmt.Errorf("users[%d].username duplicates another seed user", index)
		}
		seenUsernames[usernameNormalized] = struct{}{}

		email, emailNormalized, err := normalizeAdminEmail(seed.Email)
		if err != nil {
			return nil, fmt.Errorf("users[%d].email: %w", index, err)
		}
		if emailNormalized != "" {
			if _, ok := seenEmails[emailNormalized]; ok {
				return nil, fmt.Errorf("users[%d].email duplicates another seed user", index)
			}
			seenEmails[emailNormalized] = struct{}{}
		}

		role, ok := adminauth.ParseAdminRole(seed.Role)
		if !ok {
			return nil, fmt.Errorf("users[%d].role is invalid", index)
		}
		if err := validateManagedAdminPassword(seed.Password); err != nil {
			return nil, fmt.Errorf("users[%d].password: %w", index, err)
		}
		mustChange := true
		if seed.MustChangePassword != nil {
			mustChange = *seed.MustChangePassword
		}
		if !mustChange {
			return nil, fmt.Errorf("users[%d].must_change_password must be true for seeded admin users", index)
		}
		prepared = append(prepared, preparedAdminUserSeedRecord{
			Username:           username,
			Email:              email,
			Role:               role,
			Password:           seed.Password,
			MustChangePassword: mustChange,
		})
	}
	return prepared, nil
}
