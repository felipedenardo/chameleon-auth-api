package auth

import (
	"context"
	"errors"
	"github.com/felipedenardo/chameleon-auth-api/internal/domain/user"
	"github.com/felipedenardo/chameleon-common/pkg/base"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type IService interface {
	Register(ctx context.Context, name, email, password, role string) (*user.User, error)
	Login(ctx context.Context, email, password string) (string, *user.User, error)
	ChangePassword(ctx context.Context, id uuid.UUID, password string, password2 string) error
}

type authService struct {
	repo      user.IRepository
	jwtSecret []byte
}

func NewAuthService(repo user.IRepository, secret string) IService {
	return &authService{
		repo:      repo,
		jwtSecret: []byte(secret),
	}
}

func (s *authService) Register(ctx context.Context, name, email, password, role string) (*user.User, error) {
	existing, err := s.repo.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, errors.New("email already exists")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	newUser := &user.User{
		Model: base.Model{
			ID: uuid.New(),
		},
		Name:         name,
		Email:        email,
		PasswordHash: string(hash),
		Role:         role,
		Status:       "active",
	}

	if err := s.repo.Create(ctx, newUser); err != nil {
		return nil, err
	}

	return newUser, nil
}

func (s *authService) Login(ctx context.Context, email, password string) (string, *user.User, error) {
	foundUser, err := s.repo.FindByEmail(ctx, email)
	if err != nil {
		return "", nil, err
	}

	if foundUser == nil {
		return "", nil, errors.New("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.PasswordHash), []byte(password)); err != nil {
		return "", nil, errors.New("invalid credentials")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  foundUser.ID.String(),
		"role": foundUser.Role,
		"name": foundUser.Name,
		"exp":  time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", nil, err
	}

	return tokenString, foundUser, nil
}

func (s *authService) ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword string, newPassword string) error {
	foundUser, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		return err
	}

	if foundUser == nil {
		return errors.New("user not found")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.PasswordHash), []byte(currentPassword)); err != nil {
		return errors.New("invalid current password")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.PasswordHash), []byte(newPassword)); err == nil {
		return errors.New("new password cannot be the same as the current password")
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return s.repo.UpdatePasswordHash(ctx, userID, string(newHash))
}
