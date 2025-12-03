package repository

import (
	"context"
	"errors"
	"github.com/felipedenardo/chameleon-auth-api/internal/domain/user"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"time"
)

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) user.IRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(ctx context.Context, u *user.User) error {
	return r.db.WithContext(ctx).Create(u).Error
}

func (r *userRepository) FindByEmail(ctx context.Context, email string) (*user.User, error) {
	var u user.User
	if err := r.db.WithContext(ctx).Where("email = ?", email).First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (r *userRepository) FindByID(ctx context.Context, id uuid.UUID) (*user.User, error) {
	var u user.User
	if err := r.db.WithContext(ctx).First(&u, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *userRepository) UpdatePasswordHash(ctx context.Context, userID uuid.UUID, newHash string) error {
	updates := map[string]interface{}{
		"password_hash": newHash,
		"updated_at":    time.Now(),
	}

	result := r.db.WithContext(ctx).Model(&user.User{}).Where("id = ?", userID).Updates(updates)
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return errors.New("user not found or no changes applied")
	}
	return nil
}

func (r *userRepository) UpdateLastLoginAt(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()

	result := r.db.WithContext(ctx).
		Model(&user.User{}).
		Where("id = ?", userID).
		Update("last_login_at", now)

	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (r *userRepository) UpdateStatus(ctx context.Context, userID uuid.UUID, status string) error {
	result := r.db.WithContext(ctx).Model(&user.User{}).
		Where("id = ?", userID).
		Update("status", status)

	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errors.New("user not found or status already set")
	}
	return nil
}
