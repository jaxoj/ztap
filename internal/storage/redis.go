package storage

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisStore struct {
	client *redis.Client
}

func NewRedisStore(redisURL string) (*RedisStore, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}

	client := redis.NewClient(opts)

	// Ping to ensure the database is actually reachable
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return &RedisStore{client: client}, nil
}

// IsRevoked checks if the token JTI exists in the blacklist
func (r *RedisStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	// We prefix the key to avoid collisions with other shared redis instances
	key := "revoked:" + jti

	val, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		// Key does not exist, token is not revoked
		return false, nil
	} else if err != nil {
		// Database error (network partition, etc.) - Fail closed in high security!
		return false, err
	}

	return val == "true", nil
}

// Revoke adds a token to the blacklist with a TTL matching its remaining valid time.
func (r *RedisStore) Revoke(ctx context.Context, jti string, exp time.Time) error {
	key := "revoked:" + jti
	ttl := time.Until(exp)

	// Set the key with a value of "true" and an expiration time equal to the token's remaining validity
	return r.client.Set(ctx, key, "true", ttl).Err()
}
