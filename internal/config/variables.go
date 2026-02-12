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
	RedisHost            string
	RedisPort            string
	RedisPassword        string
	RedisDB              int
	JWTSecret            string
	Port                 string
	AppBasePath          string
	DBSSLMode            string
	BcryptCost           int
	TokenTTLHours        int
	ResetTokenTTLMinutes int
}

func Load() *Config {
	_ = godotenv.Load()

	cfg := &Config{
		DBHost:               getEnv("DB_HOST", "localhost"),
		DBPort:               getEnv("DB_PORT", "5432"),
		DBUser:               getEnv("DB_USER", ""),
		DBPassword:           getEnv("DB_PASSWORD", ""),
		DBName:               getEnv("DB_NAME", ""),
		RedisHost:            getEnv("REDIS_HOST", "localhost"),
		RedisPort:            getEnv("REDIS_PORT", "6379"),
		RedisPassword:        os.Getenv("REDIS_PASSWORD"),
		RedisDB:              getEnvInt("REDIS_DB", 0),
		JWTSecret:            os.Getenv("JWT_SECRET"),
		Port:                 getEnv("SERVER_PORT", "8081"),
		AppBasePath:          getEnv("APP_BASE_PATH", "/chameleon-auth"),
		DBSSLMode:            getEnv("DB_SSL_MODE", "disable"),
		BcryptCost:           getEnvInt("BCRYPT_COST", 10),
		TokenTTLHours:        getEnvInt("TOKEN_TTL_HOURS", 24),
		ResetTokenTTLMinutes: getEnvInt("RESET_TOKEN_TTL_MINUTES", 30),
	}

	if cfg.JWTSecret == "" {
		log.Fatal("[FATAL] JWT_SECRET is required but not set")
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
