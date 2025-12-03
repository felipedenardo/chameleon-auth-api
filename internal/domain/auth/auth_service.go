package auth

import (
	"context"
	"errors"
	"github.com/felipedenardo/chameleon-auth-api/internal/domain/user"
	"github.com/felipedenardo/chameleon-common/pkg/base"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"log"
	"time"
)

type authService struct {
	repo      user.IRepository
	cacheRepo ICacheRepository
	jwtSecret []byte
}

func NewAuthService(repo user.IRepository, cacheRepo ICacheRepository, secret string) user.IService {
	return &authService{
		repo:      repo,
		cacheRepo: cacheRepo,
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
		"jti":  uuid.New().String(),
	})

	tokenString, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", nil, err
	}

	go func() {
		err := s.repo.UpdateLastLoginAt(context.Background(), foundUser.ID)
		if err != nil {
			log.Printf("[ERROR] Failed to update last_login_at for user %s: %v", foundUser.ID.String(), err)
			return
		}
	}()

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

func (s *authService) Logout(ctx context.Context, tokenString string) error {

	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return errors.New("invalid token format")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("invalid token claims")
	}

	jti, ok := claims["jti"].(string)
	if !ok {
		return errors.New("jti claim missing")
	}

	expTime, ok := claims["exp"].(float64)
	if !ok {
		return errors.New("expiration claim missing")
	}

	ttl := time.Unix(int64(expTime), 0).Sub(time.Now())

	if ttl > 0 {
		return s.cacheRepo.BlacklistToken(ctx, jti, ttl)
	}

	return nil
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
	ttl := 30 * time.Minute

	err = s.cacheRepo.SaveResetToken(ctx, foundUser.ID.String(), resetToken, ttl)
	if err != nil {
		log.Printf("[ERROR] Failed to save reset token to cache for user %s: %v", foundUser.ID, err)
		return errors.New("internal error during token generation")
	}

	log.Printf("[INFO] Password reset token generated for user %s: %s", foundUser.ID, resetToken)

	return nil
}

// ... em internal/domain/auth/auth_service.go

// ResetPassword verifica o token no cache, o consome e atualiza a senha no DB
func (s *authService) ResetPassword(ctx context.Context, resetToken string, newPassword string) error {
	// 1. Verifica no Redis se o token existe E o consome (deleta atomicamente)
	userIDString, err := s.cacheRepo.VerifyAndConsumeResetToken(ctx, resetToken)
	if err != nil {
		// Retorna erro se o token for inválido, expirado ou já tiver sido usado.
		return errors.New("invalid or expired reset token")
	}

	// 2. Converte o UserID (string) para UUID
	userID, err := uuid.Parse(userIDString)
	if err != nil {
		return errors.New("invalid user ID associated with token")
	}

	// 3. Gera o hash da nova senha
	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// 4. Atualiza a senha no PostgreSQL (Chama o método UpdatePasswordHash que já criamos)
	return s.repo.UpdatePasswordHash(ctx, userID, string(newHash))
}
