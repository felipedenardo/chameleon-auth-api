package user

import (
	"context"

	"github.com/google/uuid"
)

type IService interface {
	Register(ctx context.Context, name, email, password string) (*User, error)
	Login(ctx context.Context, email, password string) (string, string, *User, error)
	Refresh(ctx context.Context, refreshToken string) (string, string, *User, error)
	ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword string, newPassword string, tokenString string) error
	Logout(ctx context.Context, tokenString string, refreshToken string) error
	LogoutAll(ctx context.Context, userID uuid.UUID, tokenString string) error
	ForgotPassword(ctx context.Context, email string) (string, error)
	ResetPassword(ctx context.Context, resetToken string, newPassword string) error
	DeactivateSelf(ctx context.Context, userID uuid.UUID, password, tokenString string) error
	UpdateUserStatus(ctx context.Context, userID uuid.UUID, status Status) error
}
