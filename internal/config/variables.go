package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	DBHost               string
	DBPort               string
	DBUser               string
	DBPassword           string
	DBName               string
	DBMaxOpenConns       int
	DBMaxIdleConns       int
	DBConnMaxLifetimeMin int
	DBConnMaxIdleMin     int
	RedisHost            string
	RedisPort            string
	RedisPassword        string
	RedisDB              int
	RedisDialTimeoutMs   int
	RedisReadTimeoutMs   int
	RedisWriteTimeoutMs  int
	MaxBodyBytes         int64
	LoginRateLimit       int
	LoginRateWindowSec   int
	ForgotRateLimit      int
	ForgotRateWindowSec  int
	RefreshRateLimit     int
	RefreshRateWindowSec int
	JWTIssuer            string
	JWTAudience          string
	JWTSecret            string
	ExposeResetToken     bool
	Port                 string
	AppBasePath          string
	DBSSLMode            string
	BcryptCost           int
	TokenTTLHours        int
	ResetTokenTTLMinutes int
	RefreshTokenTTLDays  int
}

func Load() *Config {
	_ = godotenv.Load()

	cfg := &Config{
		DBHost:               getEnv("DB_HOST", "localhost"),
		DBPort:               getEnv("DB_PORT", "5432"),
		DBUser:               getEnv("DB_USER", ""),
		DBPassword:           getEnv("DB_PASSWORD", ""),
		DBName:               getEnv("DB_NAME", ""),
		DBMaxOpenConns:       getEnvInt("DB_MAX_OPEN_CONNS", 25),
		DBMaxIdleConns:       getEnvInt("DB_MAX_IDLE_CONNS", 25),
		DBConnMaxLifetimeMin: getEnvInt("DB_CONN_MAX_LIFETIME_MIN", 30),
		DBConnMaxIdleMin:     getEnvInt("DB_CONN_MAX_IDLE_MIN", 5),
		RedisHost:            getEnv("REDIS_HOST", "localhost"),
		RedisPort:            getEnv("REDIS_PORT", "6379"),
		RedisPassword:        os.Getenv("REDIS_PASSWORD"),
		RedisDB:              getEnvInt("REDIS_DB", 0),
		RedisDialTimeoutMs:   getEnvInt("REDIS_DIAL_TIMEOUT_MS", 2000),
		RedisReadTimeoutMs:   getEnvInt("REDIS_READ_TIMEOUT_MS", 2000),
		RedisWriteTimeoutMs:  getEnvInt("REDIS_WRITE_TIMEOUT_MS", 2000),
		MaxBodyBytes:         int64(getEnvInt("MAX_BODY_BYTES", 1048576)),
		LoginRateLimit:       getEnvInt("LOGIN_RATE_LIMIT", 10),
		LoginRateWindowSec:   getEnvInt("LOGIN_RATE_WINDOW_SEC", 60),
		ForgotRateLimit:      getEnvInt("FORGOT_RATE_LIMIT", 5),
		ForgotRateWindowSec:  getEnvInt("FORGOT_RATE_WINDOW_SEC", 300),
		RefreshRateLimit:     getEnvInt("REFRESH_RATE_LIMIT", 30),
		RefreshRateWindowSec: getEnvInt("REFRESH_RATE_WINDOW_SEC", 60),
		JWTIssuer:            getEnv("JWT_ISSUER", "chameleon-auth-api"),
		JWTAudience:          getEnv("JWT_AUDIENCE", "chameleon-services"),
		JWTSecret:            os.Getenv("JWT_SECRET"),
		ExposeResetToken:     getEnvBool("EXPOSE_RESET_TOKEN", false),
		Port:                 getEnv("SERVER_PORT", "8081"),
		AppBasePath:          getEnv("APP_BASE_PATH", "/chameleon-auth"),
		DBSSLMode:            getEnv("DB_SSL_MODE", "disable"),
		BcryptCost:           getEnvInt("BCRYPT_COST", 10),
		TokenTTLHours:        getEnvInt("TOKEN_TTL_HOURS", 24),
		ResetTokenTTLMinutes: getEnvInt("RESET_TOKEN_TTL_MINUTES", 30),
		RefreshTokenTTLDays:  getEnvInt("REFRESH_TOKEN_TTL_DAYS", 30),
	}

	if cfg.JWTSecret == "" {
		log.Fatal("[FATAL] JWT_SECRET is required but not set")
	}
	if len(cfg.JWTSecret) < 32 {
		log.Fatal("[FATAL] JWT_SECRET must be at least 32 characters")
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	valueStr := os.Getenv(key)
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return fallback
	}
	value, err := strconv.ParseBool(valueStr)
	if err != nil {
		return fallback
	}
	return value
}
