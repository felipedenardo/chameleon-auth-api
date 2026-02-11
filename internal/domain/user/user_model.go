package user

import (
	"time"

	"github.com/felipedenardo/chameleon-common/pkg/base"
)

type User struct {
	base.Model
	Name         string     `json:"name"`
	Email        string     `json:"email"`
	PasswordHash string     `json:"-"`
	Role         string     `json:"role"`
	Status       string     `json:"status"`
	LastLoginAt  *time.Time `gorm:"column:last_login_at" json:"last_login_at,omitempty"`
	TokenVersion int        `gorm:"column:token_version;default:0" json:"-"`
}
