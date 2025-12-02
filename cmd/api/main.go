package main

import (
	"fmt"
	"github.com/felipedenardo/chameleon-auth-api/internal/app"
	"github.com/felipedenardo/chameleon-auth-api/internal/config"
	"github.com/felipedenardo/chameleon-auth-api/internal/infra/database/postgresql/migration"
	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("[INFO] No .env file found, using system environment variables.")
	}

	cfg := config.Load()

	log.Printf("Starting Auth API on port %s...", cfg.Port)

	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=UTC",
		cfg.DBHost, cfg.DBUser, cfg.DBPassword, cfg.DBName, cfg.DBPort,
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("[FATAL] Failed to connect to database: %v", err)
	}
	log.Println("Database connection established")

	m := gormigrate.New(db, gormigrate.DefaultOptions, []*gormigrate.Migration{
		&migration.ID011220251300DDLCreateInitialSchema,
	})

	if err = m.Migrate(); err != nil {
		log.Fatalf("[FATAL] Migration failed: %v", err)
	}
	log.Println("Migrations executed successfully")

	handlers := app.NewHandlerContainer(db, cfg)

	r := app.SetupRouter(handlers)

	log.Printf("[INFO] Auth API running on port %s", cfg.Port)
	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatalf("[FATAL] Server failed: %v", err)
	}
}
