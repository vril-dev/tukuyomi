package adminseed

import (
	"strings"
	"testing"
)

func TestPrepareUsersRejectsMustChangePasswordFalse(t *testing.T) {
	raw := []byte(`{"users":[{"username":"owner","email":"owner@example.test","role":"owner","password":"correct horse battery staple","must_change_password":false}]}`)
	_, err := PrepareUsers(raw, testValidators())
	if err == nil || !strings.Contains(err.Error(), "must_change_password") {
		t.Fatalf("err=%v want must_change_password rejection", err)
	}
}

func TestPrepareUsersRejectsDuplicateNormalizedUsername(t *testing.T) {
	raw := []byte(`{"users":[
{"username":"Owner","email":"a@example.test","role":"owner","password":"correct horse battery staple"},
{"username":"owner","email":"b@example.test","role":"viewer","password":"correct horse battery staple"}
]}`)
	_, err := PrepareUsers(raw, testValidators())
	if err == nil || !strings.Contains(err.Error(), "duplicates another seed user") {
		t.Fatalf("err=%v want duplicate rejection", err)
	}
}

func testValidators() Validators {
	return Validators{
		NormalizeUsername: func(raw string) (string, string, error) {
			value := strings.TrimSpace(raw)
			return value, strings.ToLower(value), nil
		},
		NormalizeEmail: func(raw string) (string, string, error) {
			value := strings.TrimSpace(raw)
			return value, strings.ToLower(value), nil
		},
		ValidatePassword: func(string) error {
			return nil
		},
	}
}
