package user

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrEmailAlreadyRegistered = errors.New("email already registered")
)

type Service struct {
	repo Repository
}

func NewService(r Repository) *Service {
	return &Service{repo: r}
}

func (s *Service) RegisterUser(user *User) (int, error) {
	existingUser, err := s.repo.GetByEmail(user.Email)
	if err != nil {
		return 0, err
	}
	if existingUser != nil {
		return 0, ErrEmailAlreadyRegistered
	}
	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		return 0, err
	}
	user.Password = hashedPassword
	return s.repo.Create(*user)
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
