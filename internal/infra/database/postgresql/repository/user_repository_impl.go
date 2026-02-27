package repository

import (
	"context"
	"errors"
	"time"

	"github.com/felipedenardo/chameleon-auth-api/internal/domain/auth"
	"github.com/felipedenardo/chameleon-auth-api/internal/domain/user"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const dbOpTimeout = 3 * time.Second

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) user.IRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(ctx context.Context, u *user.User) error {
	opCtx, cancel := context.WithTimeout(ctx, dbOpTimeout)
	defer cancel()
	return r.db.WithContext(opCtx).Create(u).Error
}

func (r *userRepository) FindByEmail(ctx context.Context, email string) (*user.User, error) {
	var u user.User
	opCtx, cancel := context.WithTimeout(ctx, dbOpTimeout)
	defer cancel()
	if err := r.db.WithContext(opCtx).Where("email = ?", email).First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (r *userRepository) FindByID(ctx context.Context, id uuid.UUID) (*user.User, error) {
	var u user.User
	opCtx, cancel := context.WithTimeout(ctx, dbOpTimeout)
	defer cancel()
	if err := r.db.WithContext(opCtx).First(&u, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *userRepository) UpdatePasswordHash(ctx context.Context, userID uuid.UUID, newHash string) error {
	opCtx, cancel := context.WithTimeout(ctx, dbOpTimeout)
	defer cancel()
	updates := map[string]interface{}{
		"password_hash": newHash,
		"updated_at":    time.Now(),
	}

	result := r.db.WithContext(opCtx).Model(&user.User{}).Where("id = ?", userID).Updates(updates)
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return auth.ErrUserNotFound
	}
	return nil
}

func (r *userRepository) UpdateLastLoginAt(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()

	opCtx, cancel := context.WithTimeout(ctx, dbOpTimeout)
	defer cancel()

	result := r.db.WithContext(opCtx).
		Model(&user.User{}).
		Where("id = ?", userID).
		Update("last_login_at", now)

	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (r *userRepository) UpdateStatus(ctx context.Context, userID uuid.UUID, status string) error {
	opCtx, cancel := context.WithTimeout(ctx, dbOpTimeout)
	defer cancel()

	result := r.db.WithContext(opCtx).Model(&user.User{}).
		Where("id = ?", userID).
		Update("status", status)

	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return auth.ErrUserNotFound
	}
	return nil
}

func (r *userRepository) IncrementTokenVersion(ctx context.Context, userID uuid.UUID) error {
	opCtx, cancel := context.WithTimeout(ctx, dbOpTimeout)
	defer cancel()

	result := r.db.WithContext(opCtx).Model(&user.User{}).
		Where("id = ?", userID).
		Update("token_version", gorm.Expr("token_version + ?", 1))

	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return auth.ErrUserNotFound
	}
	return nil
}

func (r *userRepository) GetUserTokenVersion(ctx context.Context, userID string) (int, error) {
	var version int
	opCtx, cancel := context.WithTimeout(ctx, dbOpTimeout)
	defer cancel()

	result := r.db.WithContext(opCtx).
		Model(&user.User{}).
		Select("token_version").
		Where("id = ?", userID).
		Scan(&version)

	if result.Error != nil {
		return 0, result.Error
	}

	if result.RowsAffected == 0 {
		return 0, auth.ErrUserNotFound
	}

	return version, nil
}
