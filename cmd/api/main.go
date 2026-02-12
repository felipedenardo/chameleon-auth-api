package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/felipedenardo/chameleon-auth-api/internal/app"
	"github.com/felipedenardo/chameleon-auth-api/internal/config"
	"github.com/felipedenardo/chameleon-auth-api/internal/infra/database/postgresql/migration"
	"github.com/felipedenardo/chameleon-common/pkg/validation"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// @title Auth API Microservice (Chameleon System)
// @version 1.0
// @description Este serviço é o Provedor Central de Identidade (IAM)...
// @host localhost:8081
// @BasePath /api/v1
// @schemes http
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
// @description Digite o token no formato Bearer {token}
func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("[INFO] No .env file found, using system environment variables.")
	}

	validation.SetupCustomValidator()

	cfg := config.Load()

	log.Printf("Starting Auth API on port %s...", cfg.Port)

	db := setupPostgres(cfg)
	redisClient := setupRedis(cfg)

	handlers := app.NewHandlerContainer(db, cfg, redisClient)
	r := app.SetupRouter(handlers, cfg)

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: r,
	}

	go func() {
		log.Printf("[INFO] Auth API running on port %s", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] Server failed: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server with a timeout of 5 seconds.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("[INFO] Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("[FATAL] Server forced to shutdown: %v", err)
	}

	handlers.Close()
	log.Println("[INFO] Server exiting correctly")
}

func setupPostgres(cfg *config.Config) *gorm.DB {
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=UTC",
		cfg.DBHost, cfg.DBUser, cfg.DBPassword, cfg.DBName, cfg.DBPort, cfg.DBSSLMode,
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("[FATAL] Failed to connect to PostgreSQL: %v", err)
	}
	log.Println("PostgreSQL connection established")

	m := gormigrate.New(db, gormigrate.DefaultOptions, []*gormigrate.Migration{
		&migration.ID011220251300DDLCreateInitialSchema,
	})

	if err = m.Migrate(); err != nil {
		log.Fatalf("[FATAL] Migration failed: %v", err)
	}
	log.Println("Migrations executed successfully")

	return db
}

func setupRedis(cfg *config.Config) *redis.Client {
	redisAddr := fmt.Sprintf("%s:%s", cfg.RedisHost, cfg.RedisPort)

	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	if _, err := redisClient.Ping(context.Background()).Result(); err != nil {
		log.Fatalf("[FATAL] Failed to connect to Redis: %v", err)
	}
	log.Println("Redis connection established")

	return redisClient
}

func init() {
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		v.RegisterTagNameFunc(func(fld reflect.StructField) string {
			name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
			if name == "-" {
				return ""
			}
			return name
		})
	}
}
