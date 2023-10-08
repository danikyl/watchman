package user

type User struct {
	ID       int
	Name     string
	Email    string
	Password string
}

type Repository interface {
	Create(user User) (int, error)
	GetByEmail(email string) (*User, error)
}

type UseCase interface {
	RegisterUser(user User) (int, error)
}
