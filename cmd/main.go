package main

import (
	_ "github.com/Khvan-Group/auth-service/docs"
	"github.com/Khvan-Group/auth-service/internal/api"
	"github.com/Khvan-Group/auth-service/internal/core/minio"
	"github.com/Khvan-Group/auth-service/internal/core/rabbitmq"
	"github.com/Khvan-Group/auth-service/internal/db"
	"github.com/Khvan-Group/auth-service/internal/users/service"
	"github.com/Khvan-Group/auth-service/internal/users/store"
	"github.com/Khvan-Group/common-library/logger"
	"github.com/Khvan-Group/common-library/utils"
	_ "github.com/golang-migrate/migrate/source/file"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/robfig/cron/v3"
	"net/http"
)

const SERVER_PORT = "SERVER_PORT"

// @title User Service API
// @version 1.0.3
// @description User Service.
// @host localhost:8081
// @BasePath /api/v1
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
// @BasePath /
func main() {
	start()
}

func start() {
	// init logger
	logger.InitLogger()
	logger.Logger.Info("Starting server")

	// load environments
	if err := godotenv.Load(); err != nil {
		panic(err)
	}

	// init RabbitMQ
	rabbitmq.InitRabbitMQ()

	// init db
	db.InitDB()

	// init MinIo
	minio.InitMinio()

	// init server
	port := ":" + utils.GetEnv(SERVER_PORT)
	userStore := store.New(db.DB)
	userService := service.New(userStore)
	srv := api.New(*userService, db.DB)
	r := mux.NewRouter()
	srv.AddRoutes(r)

	scheduler := cron.New()

	_, err := scheduler.AddFunc("30 * * * *", func() {
		logger.Logger.Info("Starting schedule delete tokens")
		deleteTokens(db.DB)
		logger.Logger.Info("Finishing schedule delete tokens")
	})

	if err != nil {
		panic(err)
	}

	scheduler.Start()

	logger.Logger.Fatal(http.ListenAndServe(port, r).Error())
}

func deleteTokens(db *sqlx.DB) {
	if _, err := db.Exec("delete from t_tokens where expiration_deadline >= now()"); err != nil {
		panic(err)
	}
}
