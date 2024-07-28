package api

import (
	"encoding/json"
	"github.com/Khvan-Group/auth-service/internal/users/models"
	"github.com/Khvan-Group/common-library/constants"
	"github.com/Khvan-Group/common-library/errors"
	"github.com/Khvan-Group/common-library/utils"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"golang.org/x/tools/container/intsets"
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
// @Param input body models.UserLoginRequest true "Данные для входа"
// @Success 200 {string} map[string]string
// @Failure 404 {string} errors.Error
// @Failure 400 {string} errors.Error
// @Router /auth [post]
func (a *API) Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Add(CONTENT_TYPE, APPLICATION_JSON)

	data, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	input := models.UserLoginRequest{}

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
// @Param input body models.UserCreate true "Информация о пользователе"
// @Success 200
// @Failure 400 {string} errors.CustomError
// @Router /users [post]
// @Security ApiKeyAuth
func (a *API) CreateUser(w http.ResponseWriter, r *http.Request) {
	input := models.UserCreate{}
	w.Header().Add(CONTENT_TYPE, APPLICATION_JSON)

	data, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

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
// @Accept  json
// @Produce  json
// @Param page query int false "Номер страницы"
// @Param size query int false "Количество элементов"
// @Param search query string false "Поиск по логину/email/firstName/middleName/lastName"
// @Success 200 {array} models.UserView
// @Router /admin/users [get]
// @Security ApiKeyAuth
func (a *API) FindAllUsers(w http.ResponseWriter, r *http.Request) {
	var response []models.UserView
	w.Header().Add(CONTENT_TYPE, APPLICATION_JSON)

	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil {
		page = 0
	}

	size, err := strconv.Atoi(r.URL.Query().Get("size"))
	if err != nil {
		size = intsets.MaxInt
	}

	search := r.URL.Query().Get("search")
	response = a.users.Service.FindAll(page, size, &search)

	data, err := json.Marshal(response)
	if err != nil {
		panic(err)
	}

	w.Write(data)
	w.WriteHeader(http.StatusOK)
}

// GetMyProfile
// @Summary Получение профиль текущего пользователя
// @Produce json
// @Accept json
// @Success 200 {object} models.UserView
// @Success 400 {string} errors.CustomError
// @Router /profile [get]
// @Security ApiKeyAuth
func (a *API) GetMyProfile(w http.ResponseWriter, r *http.Request) {
	response := &models.UserView{}
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

// FindUserByLogin
// @Summary Получение пользователя по логину
// @Produce json
// @Accept json
// @Success 200 {object} models.UserView
// @Success 400 {string} errors.CustomError
// @Router /admin/users/{login} [get]
// @Security ApiKeyAuth
func (a *API) FindUserByLogin(w http.ResponseWriter, r *http.Request) {
	response := &models.UserView{}
	w.Header().Add(CONTENT_TYPE, APPLICATION_JSON)

	login := mux.Vars(r)["login"]
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
// @Produce json
// @Accept json
// @Param input body models.UserUpdate true "Новая информация о пользователе"
// @Success 200
// @Failure 400 {string} errors.CustomError
// @Failure 403 {string} errors.CustomError
// @Router /admin/users [put]
// @Security ApiKeyAuth
func (a *API) UpdateUser(w http.ResponseWriter, r *http.Request) {
	input := models.UserUpdate{}
	currentUser := getJwtUser(r)
	data, err := io.ReadAll(r.Body)

	if err != nil {
		panic(err)
	}

	if err = json.Unmarshal(data, &input); err != nil {
		panic(err)
	}

	input.UpdatedBy = &currentUser.Login
	if currentUser.Role != constants.ADMIN && currentUser.Login != input.Login {
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
// @Accept json
// @Produce json
// @Success 200
// @Failure 400 {string} errors.CustomError
// @Failure 403 {string} errors.CustomError
// @Param input body models.UserChangePassword true "Старый и новый пароли"
// @Router /users/password [put]
// @Security ApiKeyAuth
func (a *API) ChangePassword(w http.ResponseWriter, r *http.Request) {
	input := models.UserChangePassword{}
	currentUserLogin := utils.ToString(context.Get(r, "login"))
	currentUserRole := utils.ToString(context.Get(r, "role"))

	data, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	if err = json.Unmarshal(data, &input); err != nil {
		panic(err)
	}

	if currentUserRole != constants.ADMIN && currentUserLogin != input.Login {
		errors.HandleError(w, errors.NewForbidden("Доступ запрещен."))
		return
	}

	if err := a.users.Service.ChangePassword(input, getJwtUser(r)); err != nil {
		errors.HandleError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ChangeRole
// @Summary Смена роли пользователя
// @Accept json
// @Produce json
// @Success 200
// @Failure 400 {string} errors.CustomError
// @Failure 403 {string} errors.CustomError
// @Param input body models.UserChangeRole true "Новая роль для пользователя"
// @Router /admin/users/role [put]
// @Security ApiKeyAuth
func (a *API) ChangeRole(w http.ResponseWriter, r *http.Request) {
	var input models.UserChangeRole
	currentUser := getJwtUser(r)

	data, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	if err = json.Unmarshal(data, &input); err != nil {
		panic(err)
	}

	if currentUser.Role != constants.ADMIN || currentUser.Login == input.Login {
		errors.HandleError(w, errors.NewForbidden("Доступ запрещен."))
		return
	}

	if err := a.users.Service.ChangeRole(input, currentUser); err != nil {
		errors.HandleError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ChangeAvatar
// @Summary Смена аватарки пользователя
// @Accept json
// @Produce json
// @Success 200
// @Failure 400 {string} errors.CustomError
// @Failure 403 {string} errors.CustomError
// @Param file body models.UserChangeRole true "Новая роль для пользователя"
// @Router /users/avatar [put]
// @Security ApiKeyAuth
func (a *API) ChangeAvatar(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		errors.HandleError(w, errors.NewBadRequest("Изображение может иметь размер не больше 10МБ."))
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		errors.HandleError(w, errors.NewInternal("Не удалось загрузить файл."))
		return
	}

	defer file.Close()

	if err := a.users.Service.ChangeAvatar(file, handler, getJwtUser(r)); err != nil {
		errors.HandleError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// DeleteUser
// @Summary Удалить пользователя
// @Accept json
// @Produce json
// @Success 200
// @Failure 400 {string} errors.CustomError
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

// ExistsByLogin
// @Summary Существует ли пользователь
// @Accept json
// @Produce json
// @Success 200 {boolean} bool
// @Failure 400 {string} errors.CustomError
// @Failure 403 {string} errors.CustomError
// @Param username path string true "Логин пользователя"
// @Router /common/{username} [get]
// @Security ApiKeyAuth
func (a *API) ExistsByLogin(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	response := a.users.Service.ExistsByLogin(username)

	data, err := json.Marshal(response)
	if err != nil {
		panic(err)
	}

	w.Write(data)
	w.WriteHeader(http.StatusOK)
}

func getJwtUser(r *http.Request) models.JwtUser {
	return models.JwtUser{
		Login: utils.ToString(context.Get(r, "login")),
		Role:  utils.ToString(context.Get(r, "role")),
	}
}
