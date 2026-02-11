package redis

import (
	"context"
	"github.com/felipedenardo/chameleon-auth-api/internal/domain/auth"
	"github.com/felipedenardo/chameleon-auth-api/internal/domain/user"
	"time"
)

type TokenVersionManager struct {
	cache auth.ICacheRepository
	repo  user.IRepository
}

func NewTokenVersionManager(c auth.ICacheRepository, r user.IRepository) *TokenVersionManager {
	return &TokenVersionManager{cache: c, repo: r}
}

func (m *TokenVersionManager) GetUserTokenVersion(ctx context.Context, userID string) (int, error) {
	key := "user:version:" + userID

	version, err := m.cache.GetUserTokenVersion(ctx, key)
	if err == nil {
		return version, nil
	}

	version, err = m.repo.GetUserTokenVersion(ctx, userID)
	if err != nil {
		return 0, err
	}

	err = m.cache.SetTokenVersion(ctx, key, version, 12*time.Hour)
	if err != nil {
		return 0, err
	}

	return version, nil
}
