package model

import "github.com/dkhvan-dev/alabs_project/auth-service/internal/blogs/model"

type User struct {
	Login      string  `json:"login"`
	Password   string  `json:"password"`
	Email      string  `json:"email"`
	FirstName  string  `json:"firstName"`
	MiddleName *string `json:"middleName"`
	LastName   string  `json:"lastName"`
	Birthdate  string  `json:"birthdate"`
	Role       Role    `json:"role"`
}

type Role struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

// DTOs

type UserCreate struct {
	Login      string  `json:"login"`
	Password   string  `json:"password"`
	RePassword string  `json:"rePassword"`
	Email      string  `json:"email"`
	FirstName  string  `json:"firstName"`
	MiddleName *string `json:"middleName"`
	LastName   string  `json:"lastName"`
	Birthdate  string  `json:"birthdate"`
}

type UserUpdate struct {
	Login      string  `json:"login"`
	FirstName  string  `json:"firstName"`
	MiddleName *string `json:"middleName"`
	LastName   string  `json:"lastName"`
	Birthdate  string  `json:"birthdate"`
}

type UserChangePassword struct {
	Login       string `json:"login"`
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
	RePassword  string `json:"rePassword"`
}

type UserView struct {
	Login      string           `json:"login"`
	Email      string           `json:"email"`
	FirstName  string           `json:"firstName"`
	MiddleName *string          `json:"middleName"`
	LastName   string           `json:"lastName"`
	Birthdate  string           `json:"birthdate"`
	Role       Role             `json:"role"`
	Blogs      []model.BlogView `json:"blogs"`
}

type UserLoginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// mapper

func (u *User) ToView() *UserView {
	return &UserView{
		Login:      u.Login,
		Email:      u.Email,
		FirstName:  u.FirstName,
		MiddleName: u.MiddleName,
		LastName:   u.LastName,
		Birthdate:  u.Birthdate,
		Role:       u.Role,
	}
}
