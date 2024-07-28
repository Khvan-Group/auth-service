package models

import "github.com/Khvan-Group/auth-service/internal/common/models"

type User struct {
	Login      string  `json:"login" db:"login"`
	CreatedAt  string  `json:"created_at" db:"created_at"`
	UpdatedAt  *string `json:"updated_at" db:"updated_at"`
	UpdatedBy  *string `json:"updated_by" db:"updated_by"`
	Password   string  `json:"password" db:"password"`
	Email      string  `json:"email" db:"email"`
	FirstName  string  `json:"first_name" db:"first_name"`
	MiddleName *string `json:"middle_name" db:"middle_name"`
	LastName   string  `json:"last_name" db:"last_name"`
	Birthdate  string  `json:"birthdate" db:"birthdate"`
	Role       Role    `json:"role" db:"role"`
	Avatar     *string `json:"avatar" db:"avatar"`
}

type Role struct {
	Code string `json:"code" db:"code"`
	Name string `json:"name" db:"name"`
}

const (
	ADMIN     = "ADMIN"
	MODERATOR = "MODERATOR"
	USER      = "USER"
)

// DTOs

type UserCreate struct {
	Login      string  `json:"login" db:"login"`
	Password   string  `json:"password" db:"password"`
	RePassword string  `json:"rePassword"`
	Email      string  `json:"email" db:"email"`
	FirstName  string  `json:"firstName" db:"first_name"`
	MiddleName *string `json:"middleName" db:"middle_name"`
	LastName   string  `json:"lastName" db:"last_name"`
	Birthdate  string  `json:"birthdate" db:"birthdate"`
}

type UserUpdate struct {
	Login      string  `json:"login" db:"login"`
	FirstName  string  `json:"firstName" db:"first_name"`
	MiddleName *string `json:"middleName" db:"middle_name"`
	LastName   string  `json:"lastName" db:"last_name"`
	Birthdate  string  `json:"birthdate" db:"birthdate"`
	UpdatedBy  *string `db:"updated_by"`
}

type UserChangePassword struct {
	Login       string `json:"login"`
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
	RePassword  string `json:"rePassword"`
}

type UserChangeRole struct {
	Login string `json:"login"`
	Role  string `json:"role"`
}

type UserView struct {
	Login      string        `json:"login" db:"login"`
	CreatedAt  string        `json:"created_at" db:"created_at"`
	UpdatedAt  *string       `json:"updated_at" db:"updated_at"`
	UpdatedBy  *string       `json:"updated_by" db:"updated_by"`
	Email      string        `json:"email" db:"email"`
	FirstName  string        `json:"firstName" db:"first_name"`
	MiddleName *string       `json:"middleName" db:"middle_name"`
	LastName   string        `json:"lastName" db:"last_name"`
	Birthdate  string        `json:"birthdate" db:"birthdate"`
	Role       Role          `json:"role" db:"role"`
	Avatar     *string       `json:"avatar" db:"avatar"`
	Wallet     models.Wallet `json:"wallet"`
}

type UserLoginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type JwtUser struct {
	Login string
	Role  string
}

// mapper

func (u *User) ToView() *UserView {
	return &UserView{
		Login:      u.Login,
		CreatedAt:  u.CreatedAt,
		UpdatedAt:  u.UpdatedAt,
		UpdatedBy:  u.UpdatedBy,
		Email:      u.Email,
		FirstName:  u.FirstName,
		MiddleName: u.MiddleName,
		LastName:   u.LastName,
		Birthdate:  u.Birthdate,
		Role:       u.Role,
		Avatar:     u.Avatar,
	}
}
