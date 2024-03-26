package repository

import (
	"context"

	"example.com/auth/models"
)

// interfaz para manejar el user struct y la base de datos con la que se trabaje
type UserRepository interface {
	InsertUser(ctx context.Context, user *models.User) error
	GetUserByID(ctx context.Context, id string) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByPhone(ctx context.Context, phone string) (*models.User, error)
	Close() error
}

var implementation UserRepository

// Se usa para que las implementaciones se hagan en tiempo real
func SetRepository(repository UserRepository) {
	implementation = repository
}

// Retorna lo que la implementación hace
func InsertUser(ctx context.Context, user *models.User) error {
	return implementation.InsertUser(ctx, user)
}

// Retorna lo que la implementación hace
func GetUserByID(ctx context.Context, id string) (*models.User, error) {
	return implementation.GetUserByID(ctx, id)
}

// Retorna lo que la implementación hace
func GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	return implementation.GetUserByEmail(ctx, email)
}

// Retorna lo que la implementación hace
func GetUserByPhone(ctx context.Context, phone string) (*models.User, error) {
	return implementation.GetUserByPhone(ctx, phone)
}

// Retorna lo que la implementación hace
func Close() error {
	return implementation.Close()
}
