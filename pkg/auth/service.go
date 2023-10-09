package auth

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	ErrInvalidToken        = errors.New("invalid token")
	ErrTokenExpired        = errors.New("token expired")
	TokenExpirationMinutes = 40
)

type Service struct{}

func NewService() *Service {
	return &Service{}
}

func (s *Service) GenerateToken(userId int, userEmail string, secret string) (string, error) {
	claims := AuthClaims{
		UserId:    userId,
		UserEmail: userEmail,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * time.Duration(TokenExpirationMinutes)).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (s *Service) VerifyToken(tokenString string, secret string) error {
	token, err := jwt.ParseWithClaims(tokenString, &AuthClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return ErrInvalidToken
	}
	claims, ok := token.Claims.(*AuthClaims)
	if !ok {
		return ErrInvalidToken
	}
	if time.Now().Unix() > claims.StandardClaims.ExpiresAt {
		return ErrTokenExpired
	}
	return nil
}
