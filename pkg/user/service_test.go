package user

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

type MockRepository struct {
	users map[string]User
}

func NewMockRepository() *MockRepository {
	return &MockRepository{
		users: make(map[string]User),
	}
}

func (m *MockRepository) Create(user User) (int, error) {
	id := len(m.users) + 1
	user.ID = id
	m.users[user.Email] = user
	return id, nil
}

func (m *MockRepository) GetByEmail(email string) (*User, error) {
	user, ok := m.users[email]
	if !ok {
		return nil, nil
	}
	return &user, nil
}

func TestRegisterUser(t *testing.T) {
	repo := NewMockRepository()
	service := NewUserService(repo)

	t.Run("Registering a new user should succeed", func(t *testing.T) {
		user := &User{
			Email:    "test@example.com",
			Password: "password123",
		}

		id, err := service.RegisterUser(user)
		if err != nil {
			t.Errorf("Expected no error, but got: %v", err)
		}

		if id <= 0 {
			t.Errorf("Expected a positive user ID, but got: %d", id)
		}

		if _, ok := repo.users[user.Email]; !ok {
			t.Errorf("Expected user to be added to the repository, but it wasn't")
		}
	})

	t.Run("Registering a user with a duplicate email should fail", func(t *testing.T) {
		repo.users["test@example.com"] = User{
			Email:    "test@example.com",
			Password: "hashedpassword",
		}

		user := &User{
			Email:    "test@example.com",
			Password: "password123",
		}

		_, err := service.RegisterUser(user)
		if err != ErrEmailAlreadyRegistered {
			t.Errorf("Expected ErrEmailAlreadyRegistered, but got: %v", err)
		}
	})

}

func TestHashPassword(t *testing.T) {
	t.Run("Hashing a valid password should succeed", func(t *testing.T) {
		password := "password123"

		hashedPassword, err := hashPassword(password)
		if err != nil {
			t.Errorf("Expected no error, but got: %v", err)
		}

		if len(hashedPassword) == 0 {
			t.Errorf("Expected non-empty hashed password")
		}
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			t.Errorf("Expected valid bcrypt hash, but got error: %v", err)
		}
	})
}
