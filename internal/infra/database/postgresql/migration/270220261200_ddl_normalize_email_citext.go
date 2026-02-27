package migration

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

var ID270220261200DDLNormalizeEmailCitext = gormigrate.Migration{
	ID: "270220261200",
	Migrate: func(tx *gorm.DB) error {
		return tx.Exec(`
			CREATE EXTENSION IF NOT EXISTS "citext";
			ALTER TABLE users
			  ALTER COLUMN email TYPE CITEXT;
			CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower ON users (lower(email));
			CREATE OR REPLACE FUNCTION set_email_lowercase()
			RETURNS TRIGGER AS $$
			BEGIN
			  NEW.email := lower(NEW.email);
			  RETURN NEW;
			END;
			$$ LANGUAGE plpgsql;

			DROP TRIGGER IF EXISTS trg_set_email_lowercase ON users;
			CREATE TRIGGER trg_set_email_lowercase
			BEFORE INSERT OR UPDATE OF email ON users
			FOR EACH ROW EXECUTE FUNCTION set_email_lowercase();
		`).Error
	},
	Rollback: func(tx *gorm.DB) error {
		return tx.Exec(`
			DROP TRIGGER IF EXISTS trg_set_email_lowercase ON users;
			DROP FUNCTION IF EXISTS set_email_lowercase();
			DROP INDEX IF EXISTS idx_users_email_lower;
			ALTER TABLE users
			  ALTER COLUMN email TYPE VARCHAR(255);
		`).Error
	},
}
