package store

import (
	"database/sql"
	"fmt"
	"github.com/Khvan-Group/auth-service/internal/users/model"
	"github.com/Khvan-Group/common-library/errors"
	"github.com/Khvan-Group/common-library/utils"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"math"
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
	ErrUserNotFound       = errors.NewNotFound("Пользователь не найден")
	ErrWrongOldPassword   = errors.NewBadRequest("Неверный текущий пароль.")
	ErrUserDelete         = errors.NewInternal("Внутрення ошибка: Не удалось удалить пользователя.")
	ErrLoginData          = errors.NewBadRequest("Неверный логин или пароль.")
)

type UserStore struct {
	db *sql.DB
}

type JwtToken struct {
	AccessToken           string
	IssuedAt              string
	ExpirationDeadline    time.Time
	RefreshToken          string
	RefreshTokenExpiresAt int64
}

func New(db *sql.DB) *UserStore {
	JwtKey = []byte(utils.GetEnv("JWT_SECRET"))
	JwtLifespanMinutes = utils.GetEnv("JWT_LIFESPAN_MINUTES")

	return &UserStore{
		db: db,
	}
}

func (s *UserStore) Login(input model.UserLoginRequest) (map[string]any, *errors.CustomError) {
	entity, err := s.GetEntityByLogin(input.Login)
	if err != nil {
		return nil, ErrUserNotFound
	}

	if err := bcrypt.CompareHashAndPassword([]byte(entity.Password), []byte(input.Password)); err != nil {
		return nil, ErrLoginData
	}

	jwtTokenInfo := generateToken(input.Login, entity.Role.Code)

	if _, err := s.db.Exec("delete from t_tokens where username = $1", jwtTokenInfo.IssuedAt); err != nil {
		panic(err)
	}

	if _, err := s.db.Exec("insert into t_tokens values ($1, $2, $3)", jwtTokenInfo.AccessToken, jwtTokenInfo.IssuedAt, jwtTokenInfo.ExpirationDeadline); err != nil {
		panic(err)
	}

	return map[string]any{
		"access_token":  jwtTokenInfo.AccessToken,
		"refresh_token": jwtTokenInfo.RefreshToken,
	}, nil
}

func (s *UserStore) FindAll(page, size int, search string) []model.UserView {
	if size == 0 {
		size = math.MaxInt
	}

	response := []model.UserView{}
	rows, err := s.db.Query("select * from t_users offset $1 limit $2", page, size)

	if err != nil {
		panic(err)
	}

	defer rows.Close()

	for rows.Next() {
		var user model.User
		var role model.Role
		var roleCode string
		err = rows.Scan(&user.Login, &user.Password, &user.Email, &user.FirstName, &user.MiddleName, &user.LastName, &user.Birthdate, &roleCode)

		if err != nil {
			panic(err)
		}

		roleRow := s.db.QueryRow("select * from t_roles where code = $1", roleCode)
		err = roleRow.Scan(&role.Code, &role.Name)
		if err != nil {
			panic(err)
		}

		user.Role = role

		response = append(response, *user.ToView())
	}

	return response
}

func (s *UserStore) FindByLogin(login string) (*model.UserView, *errors.CustomError) {
	user, err := s.GetEntityByLogin(login)

	if err != nil {
		return nil, ErrUserNotFound
	}

	return user.ToView(), nil
}

func (s *UserStore) GetEntityByLogin(login string) (*model.User, *errors.CustomError) {
	var user model.User
	var role model.Role
	var roleCode string

	row := s.db.QueryRow("select * from t_users where login = $1", login)
	err := row.Scan(&user.Login, &user.Password, &user.Email, &user.FirstName, &user.MiddleName, &user.LastName, &user.Birthdate, &roleCode)

	if err != nil {
		return nil, ErrUserNotFound
	}

	roleRow := s.db.QueryRow("select * from t_roles where code = $1", roleCode)
	err = roleRow.Scan(&role.Code, &role.Name)
	if err != nil {
		panic(err)
	}

	user.Role = role

	return &user, nil
}

func (s *UserStore) Create(input model.UserCreate) *errors.CustomError {
	exists := s.ExistsByLogin(input.Login)
	if exists {
		return ErrUserAlreadyExists
	}

	err := validateCreationUser(input)
	if err != nil {
		return err
	}

	hashPassword, _ := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	_, errExec := s.db.Exec("insert into t_users (login, password, email, first_name, middle_name, last_name, birthdate) values ($1, $2, $3, $4, $5, $6, $7)", input.Login, string(hashPassword), input.Email, input.FirstName, input.MiddleName, input.LastName, input.Birthdate)

	if errExec != nil {
		panic(err)
	}

	return nil
}

func (s *UserStore) Update(input model.UserUpdate) *errors.CustomError {
	exists := s.ExistsByLogin(input.Login)

	if !exists {
		return ErrUserNotFound
	}

	_, err := s.db.Exec("update t_users set first_name = $2, middle_name = $3, last_name = $4, birthdate = $5 where login = $1", input.Login, input.FirstName, input.MiddleName, input.LastName, input.Birthdate)
	if err != nil {
		panic(err)
	}

	return nil
}

func (s *UserStore) ChangePassword(input model.UserChangePassword) *errors.CustomError {
	exists := s.ExistsByLogin(input.Login)
	if !exists {
		return ErrUserNotFound
	}

	oldPassword := ""
	row := s.db.QueryRow("select password from t_users where login = $1", input.Login)
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

	_, err = s.db.Exec("update t_users set password = $1 where login = $2", newPassword, input.Login)
	if err != nil {
		panic(err)
	}

	return nil
}

func (s *UserStore) Delete(login string) *errors.CustomError {
	if !s.ExistsByLogin(login) {
		return ErrUserNotFound
	}

	_, err := s.db.Exec("delete from t_users where login = $1", login)
	if err != nil {
		return ErrUserDelete
	}

	return nil
}

func (s *UserStore) ExistsByLogin(login string) bool {
	userExists := false
	row := s.db.QueryRow("select exists(select 1 from t_users where login = $1)", login)
	row.Scan(&userExists)

	return userExists
}

func (s *UserStore) Logout(login string) *errors.CustomError {
	if !s.ExistsByLogin(login) {
		return ErrUserNotFound
	}

	_, err := s.db.Exec("delete from t_tokens where token = $1 and username = $2", login)
	if err != nil {
		panic(err)
	}

	return nil
}

func validateCreationUser(input model.UserCreate) *errors.CustomError {
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
