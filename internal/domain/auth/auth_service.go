package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
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

func (s *authService) Register(ctx context.Context, name, email, password string) (*user.User, error) {
	email = normalizeEmail(email)
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
		Role:         user.RoleUser,
		Status:       user.StatusActive,
	}

	if err := s.repo.Create(ctx, newUser); err != nil {
		return nil, err
	}

	return newUser, nil
}

func (s *authService) Login(ctx context.Context, email, password string) (string, string, *user.User, error) {
	email = normalizeEmail(email)
	foundUser, err := s.repo.FindByEmail(ctx, email)
	if err != nil {
		return "", "", nil, err
	}

	if foundUser == nil {
		return "", "", nil, ErrInvalidCredentials
	}

	if foundUser.Status != "active" {
		return "", "", nil, ErrAccountInactive
	}

	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.PasswordHash), []byte(password)); err != nil {
		return "", "", nil, ErrInvalidCredentials
	}

	accessToken, err := s.createAccessToken(foundUser)
	if err != nil {
		return "", "", nil, err
	}

	refreshToken, err := s.createRefreshToken(foundUser)
	if err != nil {
		return "", "", nil, err
	}

	refreshTTL := time.Duration(s.cfg.RefreshTokenTTLDays) * 24 * time.Hour
	if err := s.cacheRepo.SaveRefreshToken(ctx, foundUser.ID.String(), refreshToken, refreshTTL); err != nil {
		return "", "", nil, err
	}

	updateCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err = s.repo.UpdateLastLoginAt(updateCtx, foundUser.ID); err != nil {
		log.Printf("[ERROR] Failed to update last_login_at for user %s: %v", foundUser.ID.String(), err)
	}

	return accessToken, refreshToken, foundUser, nil
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

func (s *authService) Logout(ctx context.Context, tokenString string, refreshToken string) error {
	if err := s.invalidateToken(ctx, tokenString); err != nil {
		return err
	}

	if refreshToken == "" {
		return nil
	}

	token, err := s.parseAndValidateToken(refreshToken)
	if err != nil {
		return ErrInvalidRefreshToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return ErrInvalidRefreshToken
	}

	if typ, _ := claims["typ"].(string); typ != "refresh" {
		return ErrInvalidRefreshToken
	}

	userID, _ := claims["sub"].(string)
	if userID == "" {
		return ErrInvalidRefreshToken
	}

	cacheUserID, err := s.cacheRepo.VerifyAndConsumeRefreshToken(ctx, refreshToken)
	if err != nil || cacheUserID != userID {
		return ErrInvalidRefreshToken
	}

	return nil
}

func (s *authService) LogoutAll(ctx context.Context, userID uuid.UUID, tokenString string) error {
	if err := s.repo.IncrementTokenVersion(ctx, userID); err != nil {
		return err
	}
	return s.invalidateToken(ctx, tokenString)
}

func (s *authService) ForgotPassword(ctx context.Context, email string) (string, error) {
	email = normalizeEmail(email)
	foundUser, err := s.repo.FindByEmail(ctx, email)
	if err != nil {
		return "", err
	}
	if foundUser == nil {
		log.Printf("[INFO] Password recovery requested for non-existent email: %s", email)
		return "", nil
	}

	resetToken := uuid.New().String()
	ttl := time.Duration(s.cfg.ResetTokenTTLMinutes) * time.Minute

	err = s.cacheRepo.SaveResetToken(ctx, foundUser.ID.String(), resetToken, ttl)
	if err != nil {
		log.Printf("[ERROR] Failed to save reset token to cache for user %s: %v", foundUser.ID, err)
		return "", errors.New("internal error during token generation")
	}

	return resetToken, nil
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

func (s *authService) Refresh(ctx context.Context, refreshToken string) (string, string, *user.User, error) {
	token, err := s.parseAndValidateToken(refreshToken)
	if err != nil {
		return "", "", nil, ErrInvalidRefreshToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", nil, ErrInvalidRefreshToken
	}

	if typ, _ := claims["typ"].(string); typ != "refresh" {
		return "", "", nil, ErrInvalidRefreshToken
	}

	userID, _ := claims["sub"].(string)
	if userID == "" {
		return "", "", nil, ErrInvalidRefreshToken
	}

	cacheUserID, err := s.cacheRepo.VerifyAndConsumeRefreshToken(ctx, refreshToken)
	if err != nil || cacheUserID != userID {
		return "", "", nil, ErrInvalidRefreshToken
	}

	parsedUserID, err := uuid.Parse(userID)
	if err != nil {
		return "", "", nil, ErrInvalidRefreshToken
	}

	foundUser, err := s.repo.FindByID(ctx, parsedUserID)
	if err != nil {
		return "", "", nil, err
	}

	if foundUser.Status != user.StatusActive {
		return "", "", nil, ErrAccountInactive
	}

	tokenVersionClaim, _ := claims["token_version"].(float64)
	if int(tokenVersionClaim) != foundUser.TokenVersion {
		return "", "", nil, ErrInvalidRefreshToken
	}

	accessToken, err := s.createAccessToken(foundUser)
	if err != nil {
		return "", "", nil, err
	}

	newRefreshToken, err := s.createRefreshToken(foundUser)
	if err != nil {
		return "", "", nil, err
	}

	refreshTTL := time.Duration(s.cfg.RefreshTokenTTLDays) * 24 * time.Hour
	if err := s.cacheRepo.SaveRefreshToken(ctx, foundUser.ID.String(), newRefreshToken, refreshTTL); err != nil {
		return "", "", nil, err
	}

	return accessToken, newRefreshToken, foundUser, nil
}

func (s *authService) invalidateToken(ctx context.Context, tokenString string) error {
	token, err := s.parseAndValidateToken(tokenString)
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

func (s *authService) createAccessToken(u *user.User) (string, error) {
	claims := jwt.MapClaims{
		"sub":           u.ID.String(),
		"role":          u.Role,
		"name":          u.Name,
		"token_version": u.TokenVersion,
		"exp":           time.Now().Add(time.Duration(s.cfg.TokenTTLHours) * time.Hour).Unix(),
		"jti":           uuid.New().String(),
		"typ":           "access",
		"iss":           s.cfg.JWTIssuer,
		"aud":           s.cfg.JWTAudience,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.cfg.JWTSecret))
}

func (s *authService) createRefreshToken(u *user.User) (string, error) {
	claims := jwt.MapClaims{
		"sub":           u.ID.String(),
		"token_version": u.TokenVersion,
		"exp":           time.Now().Add(time.Duration(s.cfg.RefreshTokenTTLDays) * 24 * time.Hour).Unix(),
		"jti":           uuid.New().String(),
		"typ":           "refresh",
		"iss":           s.cfg.JWTIssuer,
		"aud":           s.cfg.JWTAudience,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.cfg.JWTSecret))
}

func (s *authService) parseAndValidateToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(s.cfg.JWTSecret), nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	return token, nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
