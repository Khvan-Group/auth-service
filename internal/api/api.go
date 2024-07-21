package api

import (
	_ "github.com/Khvan-Group/auth-service/docs"
	"github.com/Khvan-Group/auth-service/internal/users/service"
	"github.com/Khvan-Group/common-library/constants"
	"github.com/Khvan-Group/common-library/middlewares"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	httpSwagger "github.com/swaggo/http-swagger"
	"net/http"
)

type API struct {
	users service.Users
	DB    *sqlx.DB
}

func New(u service.Users, db *sqlx.DB) *API {
	return &API{
		users: u,
		DB:    db,
	}
}

func (a *API) AddRoutes(r *mux.Router) {
	appRouter := r.PathPrefix("/api/v1").Subrouter()

	addUserRoutes(appRouter, a)
	addAdminRoutes(appRouter, a)
	addInternalRoutes(appRouter, a)

	r.PathPrefix("/swagger").Handler(httpSwagger.WrapHandler)
}

func addUserRoutes(r *mux.Router, a *API) {
	r.HandleFunc("/auth", a.Login).Methods(http.MethodPost)
	r.Handle("/logout", middlewares.AuthMiddleware(http.HandlerFunc(a.Logout))).Methods(http.MethodPost)

	r.Handle("/profile", middlewares.AuthMiddleware(http.HandlerFunc(a.GetMyProfile))).Methods(http.MethodGet)
	r.HandleFunc("/users", a.CreateUser).Methods(http.MethodPost)
	r.Handle("/users", middlewares.AuthMiddleware(http.HandlerFunc(a.UpdateUser))).Methods(http.MethodPut)
	r.Handle("/users/password", middlewares.AuthMiddleware(http.HandlerFunc(a.ChangePassword))).Methods(http.MethodPut)
}

func addInternalRoutes(r *mux.Router, a *API) {
	r.Handle("/internal/{username}", middlewares.AuthMiddleware(http.HandlerFunc(a.ExistsByLogin), constants.ADMIN)).Methods(http.MethodGet)
}

func addAdminRoutes(r *mux.Router, a *API) {
	r.Handle("/admin/users", middlewares.AuthMiddleware(http.HandlerFunc(a.FindAllUsers), constants.ADMIN)).Methods(http.MethodGet)
	r.Handle("/admin/users/role", middlewares.AuthMiddleware(http.HandlerFunc(a.ChangeRole), constants.ADMIN)).Methods(http.MethodPut)
	r.Handle("/admin/users/{login}", middlewares.AuthMiddleware(http.HandlerFunc(a.FindUserByLogin), constants.ADMIN)).Methods(http.MethodGet)
	r.Handle("/admin/users/{login}", middlewares.AuthMiddleware(http.HandlerFunc(a.DeleteUser), constants.ADMIN)).Methods(http.MethodDelete)
}
