package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// testHelper contains common test setup and utilities
type testHelper struct {
	t       *testing.T
	service *Service
}

func newTestHelper(t *testing.T) *testHelper {
	t.Helper()
	service, err := NewAuthService(Config{
		SigningKey: []byte("test-signing-key"),
		BcryptCost: MinBcryptCost,
	})
	if err != nil {
		t.Fatalf("failed to create test service: %v", err)
	}
	return &testHelper{t: t, service: service}
}

func (h *testHelper) createHash(password string) string {
	h.t.Helper()
	hash, err := h.service.HashPassword(password)
	if err != nil {
		h.t.Fatalf("failed to create hash: %v", err)
	}
	return hash
}

func (h *testHelper) createToken(userID uuid.UUID, duration time.Duration) string {
	h.t.Helper()
	token, err := h.service.MakeJWT(userID, duration)
	if err != nil {
		h.t.Fatalf("failed to create token: %v", err)
	}
	return token
}

func TestNewAuthService(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr error
	}{
		{
			name:    "valid config",
			config:  Config{SigningKey: []byte("key"), BcryptCost: DefaultBcryptCost},
			wantErr: nil,
		},
		{
			name:    "empty signing key",
			config:  Config{SigningKey: nil},
			wantErr: errors.New("signing key cannot be empty"),
		},
		{
			name:    "cost too low",
			config:  Config{SigningKey: []byte("key"), BcryptCost: MinBcryptCost - 1},
			wantErr: fmt.Errorf("bcrypt cost must be between %d and %d", MinBcryptCost, MaxBcryptCost),
		},
		{
			name:    "cost too high",
			config:  Config{SigningKey: []byte("key"), BcryptCost: MaxBcryptCost + 1},
			wantErr: fmt.Errorf("bcrypt cost must be between %d and %d", MinBcryptCost, MaxBcryptCost),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAuthService(tt.config)
			if (err == nil && tt.wantErr != nil) || (err != nil && tt.wantErr == nil) {
				t.Errorf("NewAuthService() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if err != nil && tt.wantErr != nil && err.Error() != tt.wantErr.Error() {
				t.Errorf("NewAuthService() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestHashPassword(t *testing.T) {
	h := newTestHelper(t)
	tests := []struct {
		name     string
		password string
		wantErr  error
	}{
		{
			name:     "valid password",
			password: "validPass123",
			wantErr:  nil,
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  ErrPasswordTooShort,
		},
		{
			name:     "short password",
			password: "short",
			wantErr:  ErrPasswordTooShort,
		},
		{
			name:     "long password",
			password: strings.Repeat("a", MaxPasswordLength+1),
			wantErr:  ErrPasswordTooLong,
		},
		{
			name:     "max length password",
			password: strings.Repeat("a", MaxPasswordLength),
			wantErr:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := h.service.HashPassword(tt.password)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("HashPassword() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && hash == "" {
				t.Error("HashPassword() returned empty hash for valid password")
			}
		})
	}

	t.Run("same password produces different hashes", func(t *testing.T) {
		hash1 := h.createHash("samePassword123")
		hash2 := h.createHash("samePassword123")
		if hash1 == hash2 {
			t.Error("same password produced identical hashes")
		}
	})
}

func TestCheckPasswordHash(t *testing.T) {
	h := newTestHelper(t)
	validPassword := "validPass123"
	validHash := h.createHash(validPassword)

	tests := []struct {
		name     string
		password string
		hash     string
		wantErr  error
	}{
		{
			name:     "valid password",
			password: validPassword,
			hash:     validHash,
			wantErr:  nil,
		},
		{
			name:     "invalid password",
			password: "wrongPass123",
			hash:     validHash,
			wantErr:  bcrypt.ErrMismatchedHashAndPassword,
		},
		{
			name:     "empty password",
			password: "",
			hash:     validHash,
			wantErr:  ErrPasswordTooShort,
		},
		{
			name:     "empty hash",
			password: validPassword,
			hash:     "",
			wantErr:  bcrypt.ErrHashTooShort,
		},
		{
			name:     "password too long",
			password: strings.Repeat("a", MaxPasswordLength+1),
			hash:     validHash,
			wantErr:  ErrPasswordTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := h.service.CheckPasswordHash(tt.password, tt.hash)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("CheckPasswordHash() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestJWTOperations(t *testing.T) {
	h := newTestHelper(t)
	validUserID := uuid.New()

	tests := []struct {
		name      string
		setup     func() string
		wantID    uuid.UUID
		wantErr   error
		checkFunc func(error) bool
	}{
		{
			name: "valid token",
			setup: func() string {
				return h.createToken(validUserID, time.Hour)
			},
			wantID:  validUserID,
			wantErr: nil,
		},
		{
			name: "expired token",
			setup: func() string {
				return h.createToken(validUserID, -time.Hour)
			},
			wantID: uuid.Nil,
			checkFunc: func(err error) bool {
				return err != nil && strings.Contains(err.Error(), "token has expired")
			},
		},
		{
			name: "invalid token format",
			setup: func() string {
				return "invalid.token.format"
			},
			wantID:  uuid.Nil,
			wantErr: ErrInvalidToken,
		},
		{
			name: "empty token",
			setup: func() string {
				return ""
			},
			wantID:  uuid.Nil,
			wantErr: ErrEmptyToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := tt.setup()
			gotID, err := h.service.ValidateJWT(token)

			if tt.checkFunc != nil {
				if !tt.checkFunc(err) {
					t.Errorf("ValidateJWT() error = %v, failed custom check", err)
				}
			} else if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateJWT() error = %v, wantErr = %v", err, tt.wantErr)
			}

			if gotID != tt.wantID {
				t.Errorf("ValidateJWT() gotID = %v, want %v", gotID, tt.wantID)
			}
		})
	}
}

func TestGetBearerToken(t *testing.T) {
	h := newTestHelper(t)
	tests := []struct {
		name      string
		setup     func() *http.Request
		wantToken string
		wantErr   error
		checkFunc func(error) bool
	}{
		{
			name: "valid token",
			setup: func() *http.Request {
				req, err := http.NewRequest(http.MethodGet, "https://test.io", nil)
				if err != nil {
					t.Fatalf("error creating test request: %v\n", err)
				}
				req.Header.Add("Authorization", "Bearer theToken")
				return req
			},
			wantToken: "theToken",
			wantErr:   nil,
		},
		{
			name: "non-Bearer token",
			setup: func() *http.Request {
				req, err := http.NewRequest(http.MethodGet, "https://test.io", nil)
				if err != nil {
					t.Fatalf("error creating test request: %v\n", err)
				}
				req.Header.Add("Authorization", "Basic theToken")
				return req
			},
			wantToken: "",
			checkFunc: func(err error) bool {
				return err != nil && strings.Contains(err.Error(), "invalid authorization header")
			},
		},
		{
			name: "invalid token format",
			setup: func() *http.Request {
				req, err := http.NewRequest(http.MethodGet, "https://test.io", nil)
				if err != nil {
					t.Fatalf("error creating test request: %v\n", err)
				}
				req.Header.Add("Authorization", "BasicBrokenToken")
				return req
			},
			wantToken: "",
			checkFunc: func(err error) bool {
				return err != nil && strings.Contains(err.Error(), "invalid authorization header")
			},
		},
		{
			name: "empty token",
			setup: func() *http.Request {
				req, err := http.NewRequest(http.MethodGet, "https://test.io", nil)
				if err != nil {
					t.Fatalf("error creating test request: %v\n", err)
				}
				req.Header.Add("Authorization", "")
				return req
			},
			wantToken: "",
			checkFunc: func(err error) bool {
				return err != nil && strings.Contains(err.Error(), "invalid authorization header")
			},
		},
	}
}

func BenchmarkHashPassword(b *testing.B) {
	password := "benchmark-password-123"
	costs := []int{MinBcryptCost, 12, 14}

	for _, cost := range costs {
		b.Run(fmt.Sprintf("cost_%d", cost), func(b *testing.B) {
			service, _ := NewAuthService(Config{
				SigningKey: []byte("test-key"),
				BcryptCost: cost,
			})
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = service.HashPassword(password)
			}
		})
	}
}

func BenchmarkCheckPasswordHash(b *testing.B) {
	password := "benchmark-password-123"
	service, _ := NewAuthService(Config{
		SigningKey: []byte("test-key"),
		BcryptCost: MinBcryptCost,
	})
	hash, _ := service.HashPassword(password)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = service.CheckPasswordHash(password, hash)
	}
}

func BenchmarkJWTOperations(b *testing.B) {
	service, _ := NewAuthService(Config{
		SigningKey: []byte("test-key"),
		BcryptCost: MinBcryptCost,
	})
	userID := uuid.New()

	b.Run("MakeJWT", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = service.MakeJWT(userID, time.Hour)
		}
	})

	token, _ := service.MakeJWT(userID, time.Hour)
	b.Run("ValidateJWT", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = service.ValidateJWT(token)
		}
	})
}
