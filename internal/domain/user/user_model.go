package user

import (
	"time"

	"github.com/felipedenardo/chameleon-common/pkg/base"
)

type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

type Status string

const (
	StatusActive   Status = "active"
	StatusInactive Status = "inactive"
)

type User struct {
	base.Model
	Name         string     `json:"name"`
	Email        string     `json:"email"`
	PasswordHash string     `json:"-"`
	Role         Role       `json:"role"`
	Status       Status     `json:"status"`
	LastLoginAt  *time.Time `gorm:"column:last_login_at" json:"last_login_at,omitempty"`
	TokenVersion int        `gorm:"column:token_version;default:0" json:"-"`
}
