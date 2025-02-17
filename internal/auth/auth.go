package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	MinPasswordLength = 5
	MaxPasswordLength = 72 // bcrypt's maximum length
	DefaultBcryptCost = 12
	MinBcryptCost     = 10
	MaxBcryptCost     = 31
)

var (
	ErrPasswordTooShort           = errors.New("password too short\n")
	ErrPasswordTooLong            = errors.New("password too long\n")
	ErrInvalidToken               = errors.New("invalid token\n")
	ErrEmptyToken                 = errors.New("empty token\n")
	ErrInvalidAuthorizationHeader = errors.New("invalid authorization header\n")
)

type Config struct {
	SigningKey []byte
	BcryptCost int
}

type Service struct {
	config Config
}

func NewAuthService(config Config) (*Service, error) {
	if len(config.SigningKey) == 0 {
		return nil, errors.New("signing key cannot be empty")
	}
	if config.BcryptCost == 0 {
		config.BcryptCost = DefaultBcryptCost
	}
	if config.BcryptCost < MinBcryptCost || config.BcryptCost > MaxBcryptCost {
		return nil, fmt.Errorf("bcrypt cost must be between %d and %d\n", MinBcryptCost, MaxBcryptCost)
	}
	return &Service{config: config}, nil
}

func (s *Service) Authorize(header http.Header) (uuid.UUID, error) {
	token, err := s.GetBearerToken(header)
	if err != nil {
		return uuid.Nil, err
	}
	userID, err := s.ValidateJWT(token)
	if err != nil {
		return uuid.Nil, err
	}

	return userID, nil
}

func (s *Service) HashPassword(password string) (string, error) {
	if len(password) < MinPasswordLength {
		return "", ErrPasswordTooShort
	}
	if len(password) > MaxPasswordLength {
		return "", ErrPasswordTooLong
	}

	hashBytes, err := bcrypt.GenerateFromPassword([]byte(password), s.config.BcryptCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w\n", err)
	}

	return string(hashBytes), nil
}

func (s *Service) CheckPasswordHash(password, hash string) error {
	if len(password) < MinPasswordLength {
		return ErrPasswordTooShort
	}
	if len(password) > MaxPasswordLength {
		return ErrPasswordTooLong
	}

	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func (s *Service) MakeJWT(userID uuid.UUID, expiresIn time.Duration) (string, error) {
	if userID == uuid.Nil {
		return "", errors.New("invalid user ID")
	}

	now := time.Now().UTC()
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(expiresIn)),
		Subject:   userID.String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(s.config.SigningKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w\n", err)
	}

	return signedToken, nil
}

func (s *Service) ValidateJWT(tokenString string) (uuid.UUID, error) {
	if tokenString == "" {
		return uuid.Nil, ErrEmptyToken
	}

	token, err := jwt.ParseWithClaims(
		tokenString,
		&jwt.RegisteredClaims{},
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v\n", token.Header["alg"])
			}
			return s.config.SigningKey, nil
		},
	)

	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse token: %w\n", err)
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return uuid.Nil, ErrInvalidToken
	}

	return uuid.Parse(claims.Subject)
}

func (s *Service) GetBearerToken(headers http.Header) (string, error) {
	tokenString := headers.Get("Authorization")
	fmt.Println(color.GreenString("GetBearerToken: %v", tokenString))
	fields := strings.Split(tokenString, " ")

	if len(fields) > 2 || len(fields) < 2 || fields[0] != "Bearer" {
		return "", ErrInvalidAuthorizationHeader
	}

	return fields[1], nil
}

func (s *Service) MakeRefreshToken() (string, error) {
	r := make([]byte, 32)
	_, err := rand.Read(r)
	if err != nil {
		return "", fmt.Errorf("error generating random bytes: %w", err)
	}

	return hex.EncodeToString(r), nil
}
