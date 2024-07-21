package store

import (
	"fmt"
	"github.com/Khvan-Group/auth-service/internal/clients"
	wallet "github.com/Khvan-Group/auth-service/internal/common/models"
	"github.com/Khvan-Group/auth-service/internal/core/rabbitmq"
	"github.com/Khvan-Group/auth-service/internal/db"
	"github.com/Khvan-Group/auth-service/internal/users/models"
	"github.com/Khvan-Group/common-library/errors"
	"github.com/Khvan-Group/common-library/utils"
	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt"
	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"
	"math"
	"strings"
	"time"
)

var JwtKey []byte
var JwtLifespanMinutes string

var (
	ErrParsingBirthdate   = errors.NewBadRequest("Неверный формат даты рождения.")
	ErrParsingCurrentDate = errors.NewInternal("Внутрення ошибка: Не удалось получить текущую дату.")
	ErrPasswordsMatch     = errors.NewBadRequest("Пароли не совпадают.")
	ErrNewPasswordsMatch  = errors.NewBadRequest("Новые пароли не совпадают.")
	ErrInvalidBirthdate   = errors.NewBadRequest("Неверная дата рождения.")
	ErrUserAlreadyExists  = errors.NewBadRequest("Пользователь уже существует.")
	ErrUserNotFound       = errors.NewBadRequest("Пользователь не найден")
	ErrWrongOldPassword   = errors.NewBadRequest("Неверный текущий пароль.")
	ErrUserDelete         = errors.NewInternal("Внутрення ошибка: Не удалось удалить пользователя.")
	ErrLoginData          = errors.NewBadRequest("Неверный логин или пароль.")
)

type UserStore struct {
	db     *sqlx.DB
	client *resty.Client
}

type JwtToken struct {
	AccessToken           string
	IssuedAt              string
	ExpirationDeadline    time.Time
	RefreshToken          string
	RefreshTokenExpiresAt int64
}

func New(db *sqlx.DB) *UserStore {
	JwtKey = []byte(utils.GetEnv("JWT_SECRET"))
	JwtLifespanMinutes = utils.GetEnv("JWT_LIFESPAN_MINUTES")

	return &UserStore{
		db:     db,
		client: resty.New(),
	}
}

func (s *UserStore) Login(input models.UserLoginRequest) (map[string]any, *errors.CustomError) {
	var result map[string]any
	transactionErr := db.StartTransaction(func(tx *sqlx.Tx) *errors.CustomError {
		entity, err := s.GetEntityByLogin(input.Login)
		if err != nil {
			return ErrUserNotFound
		}

		if err := bcrypt.CompareHashAndPassword([]byte(entity.Password), []byte(input.Password)); err != nil {
			return ErrLoginData
		}

		jwtTokenInfo := generateToken(input.Login, entity.Role.Code)

		if _, err := s.db.Exec("delete from t_tokens where username = $1", jwtTokenInfo.IssuedAt); err != nil {
			panic(err)
		}

		if _, err := s.db.Exec("insert into t_tokens values ($1, $2, $3)", jwtTokenInfo.AccessToken, jwtTokenInfo.IssuedAt, jwtTokenInfo.ExpirationDeadline); err != nil {
			panic(err)
		}

		result = map[string]any{
			"access_token":  jwtTokenInfo.AccessToken,
			"refresh_token": jwtTokenInfo.RefreshToken,
		}

		return nil
	})

	if transactionErr != nil {
		return nil, transactionErr
	}

	return result, nil
}

func (s *UserStore) FindAll(page, size int, search *string) []models.UserView {
	if size == 0 {
		size = math.MaxInt
	}

	var response []models.UserView
	query := buildQuery(search)
	err := s.db.Select(&response, query, page, size)
	if err != nil {
		panic(err)
	}

	for i := range response {
		walletInfo, err := clients.GetWalletByUser(response[i].Login, s.client)
		if err != nil {
			panic(errors.NewInternal(fmt.Sprintf("У пользователя %s отсутствует кошелек", response[i].Login)))
		}

		response[i].Wallet = *walletInfo
	}

	return response
}

func (s *UserStore) FindByLogin(login string) (*models.UserView, *errors.CustomError) {
	user, err := s.GetEntityByLogin(login)
	if err != nil {
		return nil, err
	}

	walletInfo, err := clients.GetWalletByUser(login, s.client)
	if err != nil {
		return nil, err
	}

	response := user.ToView()
	response.Wallet = *walletInfo
	return response, nil
}

func (s *UserStore) GetEntityByLogin(login string) (*models.User, *errors.CustomError) {
	var user models.User
	login = strings.ToLower(login)

	query := `
		select u.login, u.created_at, u.updated_at, u.updated_by, u.password, u.email, 
		       u.first_name, u.middle_name, u.last_name, u.birthdate, 
		       r.code as "role.code", r.name as "role.name"
		from t_users u
			inner join t_roles r on r.code = u.role
	 	where lower(login) = $1
	`
	err := s.db.Get(&user, query, login)

	if err != nil {
		return nil, ErrUserNotFound
	}

	return &user, nil
}

func (s *UserStore) Create(input models.UserCreate) *errors.CustomError {
	return db.StartTransaction(func(tx *sqlx.Tx) *errors.CustomError {
		input.Login = strings.ToLower(input.Login)
		exists := s.ExistsByLogin(input.Login)
		if exists {
			return ErrUserAlreadyExists
		}

		err := validateCreationUser(input)
		if err != nil {
			return err
		}

		hashPassword, _ := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
		input.Password = string(hashPassword)
		query := `
			insert into t_users (login, password, email, first_name, middle_name, last_name, birthdate) 
			values (:login, :password, :email, :first_name, :middle_name, :last_name, :birthdate)
		`

		_, errExec := tx.NamedExec(query, input)
		if errExec != nil {
			panic(err)
		}

		msg := wallet.Wallet{
			User:  input.Login,
			Total: 0,
		}

		if err = rabbitmq.SendToWallet(msg); err != nil {
			return err
		}

		return nil
	})
}

func (s *UserStore) Update(input models.UserUpdate) *errors.CustomError {
	return db.StartTransaction(func(tx *sqlx.Tx) *errors.CustomError {
		input.Login = strings.ToLower(input.Login)
		exists := s.ExistsByLogin(input.Login)

		if !exists {
			return ErrUserNotFound
		}

		query := `
			update t_users set first_name = :first_name, 
							   middle_name = :middle_name, 
							   last_name = :last_name, 
							   birthdate = :birthdate,
							   updated_at = now(),
							   updated_by = :updated_by
			where lower(login) = :login
		`
		_, err := tx.NamedExec(query, input)
		if err != nil {
			panic(err)
		}

		return nil
	})
}

func (s *UserStore) ChangePassword(input models.UserChangePassword, currentUser models.JwtUser) *errors.CustomError {
	return db.StartTransaction(func(tx *sqlx.Tx) *errors.CustomError {
		input.Login = strings.ToLower(input.Login)
		entity, customErr := s.FindByLogin(input.Login)
		if customErr != nil {
			return ErrUserNotFound
		}

		if entity.Role.Code == models.ADMIN {
			return errors.NewForbidden("Нет доступа.")
		}

		oldPassword := ""
		row := tx.QueryRow("select password from t_users where lower(login) = $1", input.Login)
		row.Scan(&oldPassword)

		if err := bcrypt.CompareHashAndPassword([]byte(oldPassword), []byte(input.OldPassword)); err != nil {
			return ErrWrongOldPassword
		}

		if input.NewPassword != input.RePassword {
			return ErrNewPasswordsMatch
		}

		newPassword, err := bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			panic(err)
		}

		_, err = tx.Exec("update t_users set password = $1, updated_at = now(), updated_by = $2 where lower(login) = $3", newPassword, currentUser.Login, input.Login)
		if err != nil {
			panic(err)
		}

		return nil
	})
}

func (s *UserStore) ChangeRole(input models.UserChangeRole, currentUser models.JwtUser) *errors.CustomError {
	return db.StartTransaction(func(tx *sqlx.Tx) *errors.CustomError {
		input.Login = strings.ToLower(input.Login)
		entity, customErr := s.FindByLogin(input.Login)
		if customErr != nil {
			return ErrUserNotFound
		}

		var existsRole bool
		tx.Get(&existsRole, "select exists(select 1 from t_roles where code = $1)", input.Role)
		if !existsRole {
			return errors.NewBadRequest("Неверная переданная роль.")
		}

		if entity.Role.Code == models.ADMIN {
			return errors.NewForbidden("Доступ запрещен.")
		}

		_, err := tx.Exec("update t_users set role = $1, updated_at = now(), updated_by = $2 where lower(login) = $3", input.Role, currentUser.Login, input.Login)
		if err != nil {
			return errors.NewInternal("Failed to change role of user transaction")
		}

		return nil
	})
}

func (s *UserStore) Delete(login string) *errors.CustomError {
	return db.StartTransaction(func(tx *sqlx.Tx) *errors.CustomError {
		login = strings.ToLower(login)
		entity, err := s.FindByLogin(login)
		if err != nil {
			return ErrUserNotFound
		}

		if entity.Role.Code == models.ADMIN {
			return errors.NewForbidden("Нет доступа.")
		}

		_, execErr := tx.Exec("delete from t_users where lower(login) = $1", login)
		if execErr != nil {
			return ErrUserDelete
		}

		if err = clients.DeleteUserDependencies(login, s.client); err != nil {
			return err
		}

		return nil
	})
}

func (s *UserStore) ExistsByLogin(login string) bool {
	var userExists bool
	s.db.Get(&userExists, "select exists(select 1 from t_users where lower(login) = $1)", login)

	return userExists
}

func (s *UserStore) Logout(login string) *errors.CustomError {
	return db.StartTransaction(func(tx *sqlx.Tx) *errors.CustomError {
		login = strings.ToLower(login)
		if !s.ExistsByLogin(login) {
			return ErrUserNotFound
		}

		_, err := tx.Exec("delete from t_tokens where lower(username) = $1", login)
		if err != nil {
			panic(err)
		}

		return nil
	})
}

func validateCreationUser(input models.UserCreate) *errors.CustomError {
	birthdate, err := time.Parse("2006-01-02", input.Birthdate)
	if err != nil {
		return ErrParsingBirthdate
	}

	currentTime := time.Now().Format("2006-02-15")
	currentDate, err := time.Parse("2006-02-15", currentTime)

	if err != nil {
		return ErrParsingCurrentDate
	}

	if input.Password != input.RePassword {
		return ErrPasswordsMatch
	}

	if birthdate.After(currentDate) {
		return ErrInvalidBirthdate
	}

	return nil
}

func generateToken(username, role string) *JwtToken {
	var jwtTokenInfo JwtToken
	lifespanMinutes, err := time.ParseDuration(JwtLifespanMinutes)

	if err != nil {
		panic(fmt.Errorf("Error parsing lifespan: %v", err))
	}

	expirationTime := time.Now().Add(lifespanMinutes)
	claims := jwt.MapClaims{
		"sub":  1,
		"iss":  username,
		"exp":  expirationTime.Unix(),
		"role": role,
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessTokenString, err := accessToken.SignedString(JwtKey)
	if err != nil {
		panic(err)
	}

	refreshToken := jwt.New(jwt.SigningMethodHS256)
	refreshTokenClaims := refreshToken.Claims.(jwt.MapClaims)
	refreshTokenClaims["sub"] = 1
	refreshTokenClaims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	refreshTokenString, err := refreshToken.SignedString(JwtKey)

	jwtTokenInfo.AccessToken = accessTokenString
	jwtTokenInfo.ExpirationDeadline = expirationTime
	jwtTokenInfo.IssuedAt = username
	jwtTokenInfo.RefreshToken = refreshTokenString

	return &jwtTokenInfo
}

func buildQuery(search *string) string {
	query := `
		select u.login, u.created_at, u.updated_at, u.updated_by, u.email, u.first_name, u.middle_name, 
		       u.last_name, u.birthdate, r.code as "role.code", r.name as "role.name" 
		from t_users u
			inner join t_roles r on r.code = u.role
	`

	if search != nil && len(*search) != 0 {
		*search = strings.ToLower(*search)
		query += "where lower(u.login) like lower('%" + (*search) + "%') "
		query += "or lower(u.email) like lower('%" + (*search) + "%@') "
		query += "or lower(u.first_name) like lower('%" + (*search) + "%') "
		query += "or lower(u.middle_name) like lower('%" + (*search) + "%') "
		query += "or lower(u.last_name) like lower('%" + (*search) + "%') "
	}

	query += "offset $1 limit $2"
	return query
}
