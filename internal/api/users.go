package api

import (
	"encoding/json"
	"github.com/Khvan-Group/auth-service/internal/users/model"
	"github.com/Khvan-Group/common-library/errors"
	"github.com/Khvan-Group/common-library/utils"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"io"
	"net/http"
	"strconv"
)

const (
	APPLICATION_JSON = "application/json"
	CONTENT_TYPE     = "Content-type"
)

// Login
// @Summary Аутентификация
// @ID login
// @Accept  json
// @Produce  json
// @Param input body model.UserLoginRequest true "Данные для входа"
// @Success 200 {object} map[string]string
// @Failure 404 {object} errors.Error
// @Failure 400 {object} errors.Error
// @Router /auth [post]
func (a *API) Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Add(CONTENT_TYPE, APPLICATION_JSON)

	data, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	input := model.UserLoginRequest{}

	err = json.Unmarshal(data, &input)
	if err != nil {
		panic(err)
	}

	tokensMap, loginErr := a.users.Service.Login(input)
	if loginErr != nil {
		errors.HandleError(w, loginErr)
		return
	}

	response, err := json.Marshal(tokensMap)
	if err != nil {
		panic(err)
	}

	w.Write(response)
	w.WriteHeader(http.StatusOK)
}

// CreateUser
// @Summary Создание пользователя
// @Produce  json
// @Success 200
// @Failure 400 {string} errors.Error
// @Router /users [post]
// @Security ApiKeyAuth
func (a *API) CreateUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Add(CONTENT_TYPE, APPLICATION_JSON)

	data, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	input := model.UserCreate{}

	if err = json.Unmarshal(data, &input); err != nil {
		panic(err)
	}

	createErr := a.users.Service.Create(input)
	if createErr != nil {
		errors.HandleError(w, createErr)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// FindAllUsers
// @Summary Получение список всех пользователей
// @Produce  json
// @Success 200
// @Router /admin/users [get]
// @Security ApiKeyAuth
func (a *API) FindAllUsers(w http.ResponseWriter, r *http.Request) {
	var response []model.UserView
	w.Header().Add(CONTENT_TYPE, APPLICATION_JSON)

	page, _ := strconv.Atoi(mux.Vars(r)["page"])
	size, _ := strconv.Atoi(mux.Vars(r)["size"])

	response = a.users.Service.FindAll(page, size, "")

	data, err := json.Marshal(response)
	if err != nil {
		panic(err)
	}

	w.Write(data)
	w.WriteHeader(http.StatusOK)
}

// FindUserByLogin
// @Summary Получение пользователя по логину
// @Produce  json
// @Success 200
// @Router /admin/users/{login} [get]
// @Security ApiKeyAuth
func (a *API) FindUserByLogin(w http.ResponseWriter, r *http.Request) {
	response := &model.UserView{}
	w.Header().Add(CONTENT_TYPE, APPLICATION_JSON)

	login := utils.ToString(context.Get(r, "login"))
	response, findErr := a.users.Service.FindByLogin(login)
	if findErr != nil {
		errors.HandleError(w, findErr)
	}

	data, err := json.Marshal(response)
	if err != nil {
		panic(err)
	}

	w.Write(data)
	w.WriteHeader(http.StatusOK)
}

// UpdateUser
// @Summary Обновить пользователя
// @Produce  json
// @Success 200
// @Router /admin/users/{login} [put]
// @Security ApiKeyAuth
func (a *API) UpdateUser(w http.ResponseWriter, r *http.Request) {
	input := model.UserUpdate{}
	currentUserLogin := utils.ToString(context.Get(r, "login"))
	currentUserRole := utils.ToString(context.Get(r, "role"))
	data, err := io.ReadAll(r.Body)

	if err != nil {
		panic(err)
	}

	if err = json.Unmarshal(data, &input); err != nil {
		panic(err)
	}

	if currentUserRole != ADMIN_ROLE && currentUserLogin != input.Login {
		errors.HandleError(w, errors.NewForbidden("Доступ запрещен."))
		return
	}

	if err := a.users.Service.Update(input); err != nil {
		errors.HandleError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ChangePassword
// @Summary Смена пароля пользователя
// @Produce  json
// @Success 200
// @Router /users/password [put]
// @Security ApiKeyAuth
func (a *API) ChangePassword(w http.ResponseWriter, r *http.Request) {
	input := model.UserChangePassword{}
	currentUserLogin := utils.ToString(context.Get(r, "login"))
	currentUserRole := utils.ToString(context.Get(r, "role"))

	data, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	if err = json.Unmarshal(data, &input); err != nil {
		panic(err)
	}

	if currentUserRole != ADMIN_ROLE && currentUserLogin != input.Login {
		errors.HandleError(w, errors.NewForbidden("Доступ запрещен."))
		return
	}

	if err := a.users.Service.ChangePassword(input); err != nil {
		errors.HandleError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// DeleteUser
// @Summary Удалить пользователя
// @Produce  json
// @Success 200
// @Router /admin/users/{login} [delete]
// @Security ApiKeyAuth
func (a *API) DeleteUser(w http.ResponseWriter, r *http.Request) {
	login := mux.Vars(r)["login"]

	if err := a.users.Service.Delete(login); err != nil {
		errors.HandleError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Logout
// @Summary Выйти из учетной записи
// @Produce  json
// @Success 200
// @Router /logout [post]
// @Security ApiKeyAuth
func (a *API) Logout(w http.ResponseWriter, r *http.Request) {
	login := utils.ToString(context.Get(r, "login"))

	err := a.users.Service.Logout(login)
	if err != nil {
		errors.HandleError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}
