package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/felipedenardo/chameleon-auth-api/internal/config"
	"github.com/felipedenardo/chameleon-auth-api/internal/domain/user"
	"github.com/felipedenardo/chameleon-common/pkg/base"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type authService struct {
	repo      user.IRepository
	cacheRepo ICacheRepository
	cfg       *config.Config
}

func NewAuthService(repo user.IRepository, cacheRepo ICacheRepository, cfg *config.Config) user.IService {
	return &authService{
		repo:      repo,
		cacheRepo: cacheRepo,
		cfg:       cfg,
	}
}

func (s *authService) Register(ctx context.Context, name, email, password string, role user.Role) (*user.User, error) {
	existing, err := s.repo.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrEmailAlreadyExists
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.cfg.BcryptCost)
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
		Status:       user.StatusActive,
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
		return "", nil, ErrInvalidCredentials
	}

	if foundUser.Status != "active" {
		return "", nil, ErrAccountInactive
	}

	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.PasswordHash), []byte(password)); err != nil {
		return "", nil, ErrInvalidCredentials
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":           foundUser.ID.String(),
		"role":          foundUser.Role,
		"name":          foundUser.Name,
		"token_version": foundUser.TokenVersion,
		"exp":           time.Now().Add(time.Duration(s.cfg.TokenTTLHours) * time.Hour).Unix(),
		"jti":           uuid.New().String(),
	})

	tokenString, err := token.SignedString([]byte(s.cfg.JWTSecret))
	if err != nil {
		return "", nil, err
	}

	go func(userID uuid.UUID) {
		// Use Background context for operations that must survive the original request context
		err = s.repo.UpdateLastLoginAt(context.Background(), userID)
		if err != nil {
			log.Printf("[ERROR] Failed to update last_login_at for user %s: %v", userID.String(), err)
		}
	}(foundUser.ID)

	return tokenString, foundUser, nil
}

func (s *authService) ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword string, newPassword string, tokenString string) error {
	foundUser, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		return err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.PasswordHash), []byte(currentPassword)); err != nil {
		return ErrInvalidCurrentPassword
	}
	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.PasswordHash), []byte(newPassword)); err == nil {
		return ErrSamePassword
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.cfg.BcryptCost)
	if err != nil {
		return err
	}

	err = s.repo.UpdatePasswordHash(ctx, userID, string(newHash))
	if err != nil {
		return err
	}

	err = s.repo.IncrementTokenVersion(ctx, userID)
	if err != nil {
		log.Printf("[ERROR] Failed to increment token version for user %s: %v", userID, err)
		// Non-blocking error, but should be logged.
	}

	err = s.invalidateToken(ctx, tokenString)
	if err != nil {
		return fmt.Errorf("failed to invalidate token after password change: %v", err)
	}

	return err
}

func (s *authService) Logout(ctx context.Context, tokenString string) error {
	return s.invalidateToken(ctx, tokenString)
}

func (s *authService) ForgotPassword(ctx context.Context, email string) error {
	foundUser, err := s.repo.FindByEmail(ctx, email)
	if err != nil {
		return err
	}
	if foundUser == nil {
		log.Printf("[INFO] Password recovery requested for non-existent email: %s", email)
		return nil
	}

	resetToken := uuid.New().String()
	ttl := time.Duration(s.cfg.ResetTokenTTLMinutes) * time.Minute

	err = s.cacheRepo.SaveResetToken(ctx, foundUser.ID.String(), resetToken, ttl)
	if err != nil {
		log.Printf("[ERROR] Failed to save reset token to cache for user %s: %v", foundUser.ID, err)
		return errors.New("internal error during token generation")
	}

	log.Printf("[INFO] Password reset token generated for user %s: %s", foundUser.ID, resetToken)

	return nil
}

func (s *authService) ResetPassword(ctx context.Context, resetToken string, newPassword string) error {
	userIDString, err := s.cacheRepo.VerifyAndConsumeResetToken(ctx, resetToken)
	if err != nil {
		return ErrInvalidResetToken
	}

	userID, err := uuid.Parse(userIDString)
	if err != nil {
		return ErrInvalidUserID
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.cfg.BcryptCost)
	if err != nil {
		return err
	}

	err = s.repo.IncrementTokenVersion(ctx, userID)
	if err != nil {
		log.Printf("[ERROR] Failed to increment token version for user %s: %v", userID, err)
	}

	return s.repo.UpdatePasswordHash(ctx, userID, string(newHash))
}

func (s *authService) DeactivateSelf(ctx context.Context, userID uuid.UUID, currentPassword string, tokenString string) error {
	foundUser, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if foundUser == nil {
		return errors.New("user not found")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.PasswordHash), []byte(currentPassword)); err != nil {
		return ErrInvalidCurrentPassword
	}

	err = s.repo.UpdateStatus(ctx, userID, string(user.StatusInactive))
	if err != nil {
		return err
	}

	err = s.repo.IncrementTokenVersion(ctx, userID)
	if err != nil {
		log.Printf("[ERROR] Failed to increment token version for user %s: %v", userID, err)
	}

	err = s.invalidateToken(ctx, tokenString)
	if err != nil {
		return fmt.Errorf("failed to invalidate token after deactivation: %w", err)
	}

	return err
}

func (s *authService) UpdateUserStatus(ctx context.Context, userID uuid.UUID, status user.Status) error {
	return s.repo.UpdateStatus(ctx, userID, string(status))
}

func (s *authService) invalidateToken(ctx context.Context, tokenString string) error {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return errors.New("formato de token inválido")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("claims inválidas")
	}

	jti, _ := claims["jti"].(string)
	expTime, _ := claims["exp"].(float64)
	ttl := time.Until(time.Unix(int64(expTime), 0))

	if ttl > 0 && jti != "" {
		return s.cacheRepo.BlacklistToken(ctx, jti, ttl)
	}

	return nil
}
