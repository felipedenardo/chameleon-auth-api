package redis

import (
	"context"
	"errors"
	"github.com/felipedenardo/chameleon-auth-api/internal/domain/auth"
	"github.com/redis/go-redis/v9"
	"time"
)

type cacheRepository struct {
	client *redis.Client
}

func NewCacheRepository(client *redis.Client) auth.ICacheRepository {
	return &cacheRepository{client: client}
}

func (r *cacheRepository) BlacklistToken(ctx context.Context, jti string, ttl time.Duration) error {
	return r.client.Set(ctx, jti, "1", ttl).Err()
}

func (r *cacheRepository) IsTokenBlacklisted(ctx context.Context, jti string) (bool, error) {
	cmd := r.client.Exists(ctx, jti)
	if cmd.Err() != nil {
		return false, cmd.Err()
	}
	return cmd.Val() == 1, nil
}

func (r *cacheRepository) SaveResetToken(ctx context.Context, userID string, resetToken string, ttl time.Duration) error {
	return r.client.Set(ctx, resetToken, userID, ttl).Err()
}

func (r *cacheRepository) VerifyAndConsumeResetToken(ctx context.Context, resetToken string) (string, error) {

	cmd := r.client.GetDel(ctx, resetToken)

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
func (r *cacheRepository) GetUserTokenVersion(ctx context.Context, key string) (int, error) {
	val, err := r.client.Get(ctx, key).Int()
	if err != nil {
		return 0, err
	}

	return val, nil
}

func (r *cacheRepository) SetTokenVersion(ctx context.Context, key string, version int, expiration time.Duration) error {
	err := r.client.Set(ctx, key, version, expiration).Err()
	if err != nil {
		return err
	}
	return nil
}
