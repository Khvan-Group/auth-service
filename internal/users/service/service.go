package service

import (
	"github.com/Khvan-Group/auth-service/internal/users/model"
	"github.com/Khvan-Group/common-library/errors"
)

type UserService interface {
	Login(input model.UserLoginRequest) (map[string]any, *errors.CustomError)
	FindAll(page, size int, search string) []model.UserView
	FindByLogin(login string) (*model.UserView, *errors.CustomError)
	GetEntityByLogin(login string) (*model.User, *errors.CustomError)
	Create(input model.UserCreate) *errors.CustomError
	Update(input model.UserUpdate) *errors.CustomError
	ChangePassword(input model.UserChangePassword) *errors.CustomError
	Delete(login string) *errors.CustomError
	ExistsByLogin(login string) bool
	Logout(login string) *errors.CustomError
}

type Users struct {
	Service UserService
}

func New(s UserService) *Users {
	return &Users{
		Service: s,
	}
}
