package db

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/dkhvan-dev/alabs_project/common-libraries/utils"
	"github.com/golang-migrate/migrate"
	"github.com/golang-migrate/migrate/database/postgres"
	_ "github.com/golang-migrate/migrate/source/file"
	_ "github.com/lib/pq"
	"os"
)

var DB *sql.DB

func InitDB() {
	dbHost := utils.GetEnv("DB_HOST")
	dbName := utils.GetEnv("DB_NAME")
	dbUser := utils.GetEnv("DB_USER")
	dbPass := utils.GetEnv("DB_PASS")
	dbPort := utils.GetEnv("DB_PORT")
	sslmode := utils.GetEnv("SSLMODE")
	dbUrl := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", dbUser, dbPass, dbHost, dbPort, dbName, sslmode)

	db, err := sql.Open("postgres", dbUrl)
	if err != nil {
		panic(err)
	}

	if db.Ping() != nil {
		panic(err)
	}

	DB = db

	migrateSql(db)
}

func migrateSql(db *sql.DB) {
	migrationsPath := "file://internal/migrations"
	dbName := os.Getenv("DB_NAME")
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		panic(err)
	}

	migrator, err := migrate.NewWithDatabaseInstance(migrationsPath, dbName, driver)
	if err != nil {
		panic(err)
	}

	if err = migrator.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		panic(err)
	}
}
