package migration

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

var ID011220251300DDLCreateInitialSchema = gormigrate.Migration{
	ID: "011220251300",
	Migrate: func(tx *gorm.DB) error {
		return tx.Exec(`
          CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

          CREATE TABLE users (
             id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
             name VARCHAR(255) NOT NULL,
             email VARCHAR(255) NOT NULL UNIQUE,
             password_hash VARCHAR(255) NOT NULL,
             role VARCHAR(50) NOT NULL, 
             status VARCHAR(20) NOT NULL DEFAULT 'active',
             token_version INT NOT NULL DEFAULT 0,
             last_login_at TIMESTAMP,
             created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
             updated_at TIMESTAMP,
             deleted_at TIMESTAMP
          );

          CREATE INDEX idx_users_email ON users(email);
            
          COMMENT ON TABLE users IS 'Tabela central de identidades (SSO).';
          COMMENT ON COLUMN users.role IS 'Define o nível de acesso.';
       `).Error
	},
	Rollback: func(tx *gorm.DB) error {
		return tx.Exec(`
           DROP TABLE IF EXISTS users;
           DROP EXTENSION IF EXISTS "uuid-ossp";
       `).Error
	},
}
