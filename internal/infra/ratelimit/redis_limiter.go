package ratelimit

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

const allowLua = `
local current = redis.call("INCR", KEYS[1])
if current == 1 then
  redis.call("EXPIRE", KEYS[1], ARGV[1])
end
return current
`

type Limiter struct {
	client *redis.Client
}

func New(client *redis.Client) *Limiter {
	return &Limiter{client: client}
}

func (l *Limiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	seconds := int(window.Seconds())
	if seconds <= 0 {
		seconds = 1
	}

	val, err := l.client.Eval(ctx, allowLua, []string{key}, seconds).Int()
	if err != nil {
		return false, err
	}

	return val <= limit, nil
}
