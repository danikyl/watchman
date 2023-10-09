package auth

import (
	"github.com/dgrijalva/jwt-go"
)

type AuthClaims struct {
	UserId         int    `json:"user_id"`
	UserEmail      string `json:"email"`
	StandardClaims jwt.StandardClaims
}

// Valid implements jwt.Claims.
func (a AuthClaims) Valid() error {
	return nil
}

type AuthUseCase interface {
	GenerateToken(userId int, userEmail string, secret string) (string, error)
	VerifyToken(token string, secret string)
}
