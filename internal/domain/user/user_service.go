package user

import (
	"context"
	"github.com/google/uuid"
)

type IService interface {
	Register(ctx context.Context, name, email, password, role string) (*User, error)
	Login(ctx context.Context, email, password string) (string, *User, error)
	ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword string, newPassword string) error
}
