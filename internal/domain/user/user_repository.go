package user

import (
	"context"
	"github.com/google/uuid"
)

type IRepository interface {
	Create(ctx context.Context, user *User) error
	FindByEmail(ctx context.Context, email string) (*User, error)
	FindByID(ctx context.Context, id uuid.UUID) (*User, error)
	UpdatePasswordHash(ctx context.Context, userID uuid.UUID, newHash string) error
}
