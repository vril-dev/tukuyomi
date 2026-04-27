package adminseed

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"tukuyomi/internal/adminauth"
)

const (
	StartupUsersSeedName = "admin-users.json"
	MaxUserSeedRecords   = 16

	BootstrapUsernameEnv = "TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME"
	BootstrapEmailEnv    = "TUKUYOMI_ADMIN_BOOTSTRAP_EMAIL"
	BootstrapPasswordEnv = "TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD"
)

type UserSeedFile struct {
	Users []UserSeedRecord `json:"users"`
}

type UserSeedRecord struct {
	Username           string `json:"username"`
	Email              string `json:"email"`
	Role               string `json:"role"`
	Password           string `json:"password"`
	MustChangePassword *bool  `json:"must_change_password"`
}

type PreparedUserSeedRecord struct {
	Username           string
	Email              string
	Role               adminauth.AdminRole
	Password           string
	MustChangePassword bool
}

type Validators struct {
	NormalizeUsername func(string) (string, string, error)
	NormalizeEmail    func(string) (string, string, error)
	ValidatePassword  func(string) error
}

func PrepareUsers(raw []byte, validators Validators) ([]PreparedUserSeedRecord, error) {
	if validators.NormalizeUsername == nil || validators.NormalizeEmail == nil || validators.ValidatePassword == nil {
		return nil, fmt.Errorf("admin seed validators are required")
	}

	var payload UserSeedFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("admin users seed must contain a single JSON object")
	}
	if len(payload.Users) > MaxUserSeedRecords {
		return nil, fmt.Errorf("too many admin user seed records")
	}

	seenUsernames := map[string]struct{}{}
	seenEmails := map[string]struct{}{}
	prepared := make([]PreparedUserSeedRecord, 0, len(payload.Users))
	for index, seed := range payload.Users {
		username, usernameNormalized, err := validators.NormalizeUsername(seed.Username)
		if err != nil {
			return nil, fmt.Errorf("users[%d].username: %w", index, err)
		}
		if _, ok := seenUsernames[usernameNormalized]; ok {
			return nil, fmt.Errorf("users[%d].username duplicates another seed user", index)
		}
		seenUsernames[usernameNormalized] = struct{}{}

		email, emailNormalized, err := validators.NormalizeEmail(seed.Email)
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
		if err := validators.ValidatePassword(seed.Password); err != nil {
			return nil, fmt.Errorf("users[%d].password: %w", index, err)
		}
		mustChange := true
		if seed.MustChangePassword != nil {
			mustChange = *seed.MustChangePassword
		}
		if !mustChange {
			return nil, fmt.Errorf("users[%d].must_change_password must be true for seeded admin users", index)
		}
		prepared = append(prepared, PreparedUserSeedRecord{
			Username:           username,
			Email:              email,
			Role:               role,
			Password:           seed.Password,
			MustChangePassword: mustChange,
		})
	}
	return prepared, nil
}
