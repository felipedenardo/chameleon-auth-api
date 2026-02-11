package auth

import "errors"

var (
	ErrUserNotFound           = errors.New("user not found")
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrAccountInactive        = errors.New("account is inactive or suspended")
	ErrEmailAlreadyExists     = errors.New("email already exists")
	ErrInvalidCurrentPassword = errors.New("invalid current password")
	ErrSamePassword           = errors.New("new password cannot be the same as the current password")
	ErrInvalidResetToken      = errors.New("invalid or expired reset token")
	ErrInvalidUserID          = errors.New("invalid user ID associated with token")
)
