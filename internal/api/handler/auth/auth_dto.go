package auth

import (
	"github.com/felipedenardo/chameleon-auth-api/internal/domain/user"
	"github.com/felipedenardo/chameleon-common/pkg/base"
)

type RegisterRequest struct {
	Name     string `json:"name" validate:"required,min=3,max=100"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=6"`
	Role     string `json:"role" validate:"required,oneof=admin professional"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type UserResponse struct {
	base.ModelDTO
	Name   string `json:"name"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	Status string `json:"status"`
}

type LoginResponse struct {
	Token string       `json:"token"`
	User  UserResponse `json:"user"`
}

func ToUserResponse(u *user.User) UserResponse {
	return UserResponse{
		ModelDTO: base.ToDTO(u.Model),
		Name:     u.Name,
		Email:    u.Email,
		Role:     u.Role,
		Status:   u.Status,
	}
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
	ConfirmPassword string `json:"confirm_password" validate:"required,eqfield=NewPassword"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type ResetPasswordRequest struct {
	Token           string `json:"token" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
	ConfirmPassword string `json:"confirm_password" validate:"required,eqfield=NewPassword"`
}

type DeactivateRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
}

type StatusUpdateRequest struct {
	NewStatus string `json:"status" validate:"required,oneof=active inactive suspended"`
}
