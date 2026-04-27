package adminauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	passwordHashAlgorithm = "argon2id"
	passwordHashVersion   = 19
	maxPasswordBytes      = 1024
	maxPasswordHashBytes  = 512
)

var (
	ErrInvalidPassword         = errors.New("invalid password")
	ErrInvalidPasswordHash     = errors.New("invalid password hash")
	ErrUnsupportedPasswordHash = errors.New("unsupported password hash")
)

type PasswordHashParams struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var defaultPasswordHashParams = PasswordHashParams{
	MemoryKiB:   64 * 1024,
	Iterations:  3,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

func HashPassword(password string) (string, error) {
	return hashPasswordWithParams(password, defaultPasswordHashParams)
}

func VerifyPassword(encodedHash, password string) (bool, error) {
	if password == "" {
		return false, nil
	}
	if len(password) > maxPasswordBytes {
		return false, ErrInvalidPassword
	}

	params, salt, expected, err := parsePasswordHash(encodedHash)
	if err != nil {
		return false, err
	}

	got := argon2.IDKey([]byte(password), salt, params.Iterations, params.MemoryKiB, params.Parallelism, params.KeyLength)
	return subtle.ConstantTimeCompare(got, expected) == 1, nil
}

func hashPasswordWithParams(password string, params PasswordHashParams) (string, error) {
	if password == "" || len(password) > maxPasswordBytes {
		return "", ErrInvalidPassword
	}
	if err := validatePasswordHashParams(params); err != nil {
		return "", err
	}

	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, params.Iterations, params.MemoryKiB, params.Parallelism, params.KeyLength)

	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		passwordHashAlgorithm,
		passwordHashVersion,
		params.MemoryKiB,
		params.Iterations,
		params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func parsePasswordHash(encodedHash string) (PasswordHashParams, []byte, []byte, error) {
	if encodedHash == "" || len(encodedHash) > maxPasswordHashBytes || strings.TrimSpace(encodedHash) != encodedHash {
		return PasswordHashParams{}, nil, nil, ErrInvalidPasswordHash
	}

	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" {
		return PasswordHashParams{}, nil, nil, ErrInvalidPasswordHash
	}
	if parts[1] != passwordHashAlgorithm {
		return PasswordHashParams{}, nil, nil, ErrUnsupportedPasswordHash
	}
	if parts[2] != fmt.Sprintf("v=%d", passwordHashVersion) {
		return PasswordHashParams{}, nil, nil, ErrUnsupportedPasswordHash
	}

	params, err := parsePasswordHashParamField(parts[3])
	if err != nil {
		return PasswordHashParams{}, nil, nil, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return PasswordHashParams{}, nil, nil, ErrInvalidPasswordHash
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return PasswordHashParams{}, nil, nil, ErrInvalidPasswordHash
	}
	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(expected))
	if err := validatePasswordHashParams(params); err != nil {
		return PasswordHashParams{}, nil, nil, err
	}

	return params, salt, expected, nil
}

func parsePasswordHashParamField(raw string) (PasswordHashParams, error) {
	var params PasswordHashParams
	var seenMemory, seenIterations, seenParallelism bool
	for _, field := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(field, "=")
		if !ok || key == "" || value == "" {
			return PasswordHashParams{}, ErrInvalidPasswordHash
		}
		switch key {
		case "m":
			parsed, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return PasswordHashParams{}, ErrInvalidPasswordHash
			}
			params.MemoryKiB = uint32(parsed)
			seenMemory = true
		case "t":
			parsed, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return PasswordHashParams{}, ErrInvalidPasswordHash
			}
			params.Iterations = uint32(parsed)
			seenIterations = true
		case "p":
			parsed, err := strconv.ParseUint(value, 10, 8)
			if err != nil {
				return PasswordHashParams{}, ErrInvalidPasswordHash
			}
			params.Parallelism = uint8(parsed)
			seenParallelism = true
		default:
			return PasswordHashParams{}, ErrInvalidPasswordHash
		}
	}
	if !seenMemory || !seenIterations || !seenParallelism {
		return PasswordHashParams{}, ErrInvalidPasswordHash
	}
	return params, nil
}

func validatePasswordHashParams(params PasswordHashParams) error {
	switch {
	case params.MemoryKiB < 8 || params.MemoryKiB > 256*1024:
		return ErrInvalidPasswordHash
	case params.Iterations < 1 || params.Iterations > 10:
		return ErrInvalidPasswordHash
	case params.Parallelism < 1 || params.Parallelism > 4:
		return ErrInvalidPasswordHash
	case params.SaltLength < 16 || params.SaltLength > 64:
		return ErrInvalidPasswordHash
	case params.KeyLength < 16 || params.KeyLength > 64:
		return ErrInvalidPasswordHash
	default:
		return nil
	}
}
