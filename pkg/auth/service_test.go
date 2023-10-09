package auth

import (
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func TestGenerateToken(t *testing.T) {
	secret := "your-secret-key"
	service := NewService()

	// Test case 1: Generating a token
	userId := 1
	userEmail := "user@example.com"
	token, err := service.GenerateToken(userId, userEmail, secret)
	if err != nil {
		t.Errorf("Error generating token: %v", err)
	}

	// Test case 2: Verifying the generated token
	err = service.VerifyToken(token, secret)
	if err != nil {
		t.Errorf("Error verifying token: %v", err)
	}
}

func TestVerifyToken(t *testing.T) {
	secret := "your-secret-key"
	service := NewService()

	// Generate a token
	userId := 1
	userEmail := "user@example.com"
	token, err := service.GenerateToken(userId, userEmail, secret)
	if err != nil {
		t.Fatalf("Error generating token: %v", err)
	}

	// Test case 1: Verifying a valid token
	err = service.VerifyToken(token, secret)
	if err != nil {
		t.Errorf("Error verifying valid token: %v", err)
	}

	// Test case 2: Verifying an invalid token with an incorrect secret
	invalidSecret := "invalid-secret-key"
	err = service.VerifyToken(token, invalidSecret)
	if err != ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken, got: %v", err)
	}

	// Test case 3: Verifying an expired token
	// Simulate an expired token by setting a very short expiration time (1 second)
	expiredClaims := AuthClaims{
		UserId:    2,
		UserEmail: "expired@example.com",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(-time.Second).Unix(),
		},
	}
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	expiredTokenString, err := expiredToken.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Error generating expired token: %v", err)
	}
	err = service.VerifyToken(expiredTokenString, secret)
	if err != ErrTokenExpired {
		t.Errorf("Expected ErrTokenExpired, got: %v", err)
	}
}
