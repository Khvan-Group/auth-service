package service

import (
	"github.com/Khvan-Group/auth-service/internal/users/models"
	"github.com/Khvan-Group/common-library/errors"
)

type UserService interface {
	Login(input models.UserLoginRequest) (map[string]any, *errors.CustomError)
	FindAll(page, size int, search *string) []models.UserView
	FindByLogin(login string) (*models.UserView, *errors.CustomError)
	GetEntityByLogin(login string) (*models.User, *errors.CustomError)
	Create(input models.UserCreate) *errors.CustomError
	Update(input models.UserUpdate) *errors.CustomError
	ChangePassword(input models.UserChangePassword, currentUser models.JwtUser) *errors.CustomError
	ChangeRole(input models.UserChangeRole, currentUser models.JwtUser) *errors.CustomError
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
