package auth

import (
	"context"
	"time"
)

type ICacheRepository interface {
	BlacklistToken(ctx context.Context, jti string, ttl time.Duration) error
	IsTokenBlacklisted(ctx context.Context, jti string) (bool, error)
	SaveResetToken(ctx context.Context, userID string, resetToken string, ttl time.Duration) error
	VerifyAndConsumeResetToken(ctx context.Context, resetToken string) (userID string, err error)
	SaveRefreshToken(ctx context.Context, userID string, refreshToken string, ttl time.Duration) error
	VerifyAndConsumeRefreshToken(ctx context.Context, refreshToken string) (userID string, err error)
	GetUserTokenVersion(ctx context.Context, key string) (int, error)
	SetTokenVersion(ctx context.Context, key string, version int, expiration time.Duration) error
}
