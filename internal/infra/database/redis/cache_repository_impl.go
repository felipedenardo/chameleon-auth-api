package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/felipedenardo/chameleon-auth-api/internal/domain/auth"
	"github.com/redis/go-redis/v9"
)

type cacheRepository struct {
	client *redis.Client
}

const (
	cacheOpTimeout    = 2 * time.Second
	blacklistKeyPrefx = "auth:blacklist:"
	resetKeyPrefix    = "auth:reset:"
	refreshKeyPrefix  = "auth:refresh:"
	tokenVerKeyPrefix = "auth:token_version:"
)

func NewCacheRepository(client *redis.Client) auth.ICacheRepository {
	return &cacheRepository{client: client}
}

func (r *cacheRepository) BlacklistToken(ctx context.Context, jti string, ttl time.Duration) error {
	opCtx, cancel := context.WithTimeout(ctx, cacheOpTimeout)
	defer cancel()
	return r.client.Set(opCtx, blacklistKeyPrefx+jti, "1", ttl).Err()
}

func (r *cacheRepository) IsTokenBlacklisted(ctx context.Context, jti string) (bool, error) {
	opCtx, cancel := context.WithTimeout(ctx, cacheOpTimeout)
	defer cancel()
	cmd := r.client.Exists(opCtx, blacklistKeyPrefx+jti)
	if cmd.Err() != nil {
		return false, cmd.Err()
	}
	return cmd.Val() == 1, nil
}

func (r *cacheRepository) SaveResetToken(ctx context.Context, userID string, resetToken string, ttl time.Duration) error {
	key := resetKeyPrefix + hashToken(resetToken)
	opCtx, cancel := context.WithTimeout(ctx, cacheOpTimeout)
	defer cancel()
	return r.client.Set(opCtx, key, userID, ttl).Err()
}

func (r *cacheRepository) VerifyAndConsumeResetToken(ctx context.Context, resetToken string) (string, error) {
	key := resetKeyPrefix + hashToken(resetToken)
	opCtx, cancel := context.WithTimeout(ctx, cacheOpTimeout)
	defer cancel()
	cmd := r.client.GetDel(opCtx, key)

	if cmd.Err() != nil {
		if errors.Is(cmd.Err(), redis.Nil) {
			return "", errors.New("reset token is invalid or expired")
		}
		return "", cmd.Err()
	}

	userID := cmd.Val()

	if userID == "" {
		return "", errors.New("reset token is invalid or expired")
	}

	return userID, nil
}

func (r *cacheRepository) SaveRefreshToken(ctx context.Context, userID string, refreshToken string, ttl time.Duration) error {
	key := refreshKeyPrefix + hashToken(refreshToken)
	opCtx, cancel := context.WithTimeout(ctx, cacheOpTimeout)
	defer cancel()
	return r.client.Set(opCtx, key, userID, ttl).Err()
}

func (r *cacheRepository) VerifyAndConsumeRefreshToken(ctx context.Context, refreshToken string) (string, error) {
	key := refreshKeyPrefix + hashToken(refreshToken)
	opCtx, cancel := context.WithTimeout(ctx, cacheOpTimeout)
	defer cancel()
	cmd := r.client.GetDel(opCtx, key)
	if cmd.Err() != nil {
		if errors.Is(cmd.Err(), redis.Nil) {
			return "", errors.New("refresh token is invalid or expired")
		}
		return "", cmd.Err()
	}

	userID := cmd.Val()
	if userID == "" {
		return "", errors.New("refresh token is invalid or expired")
	}

	return userID, nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func (r *cacheRepository) GetUserTokenVersion(ctx context.Context, key string) (int, error) {
	opCtx, cancel := context.WithTimeout(ctx, cacheOpTimeout)
	defer cancel()
	val, err := r.client.Get(opCtx, tokenVerKeyPrefix+key).Int()
	if err != nil {
		return 0, err
	}

	return val, nil
}

func (r *cacheRepository) SetTokenVersion(ctx context.Context, key string, version int, expiration time.Duration) error {
	opCtx, cancel := context.WithTimeout(ctx, cacheOpTimeout)
	defer cancel()
	err := r.client.Set(opCtx, tokenVerKeyPrefix+key, version, expiration).Err()
	if err != nil {
		return err
	}
	return nil
}
