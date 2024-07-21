package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	customErrors "github.com/Khvan-Group/common-library/errors"
	"github.com/Khvan-Group/common-library/utils"
	"github.com/golang-migrate/migrate"
	"github.com/golang-migrate/migrate/database/postgres"
	_ "github.com/golang-migrate/migrate/source/file"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"os"
)

var DB *sqlx.DB

func InitDB() {
	dbHost := utils.GetEnv("DB_HOST")
	dbName := utils.GetEnv("DB_NAME")
	dbUser := utils.GetEnv("DB_USER")
	dbPass := utils.GetEnv("DB_PASS")
	dbPort := utils.GetEnv("DB_PORT")
	sslmode := utils.GetEnv("SSLMODE")
	dbUrl := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", dbUser, dbPass, dbHost, dbPort, dbName, sslmode)

	db, err := sqlx.Open("postgres", dbUrl)
	if err != nil {
		panic(err)
	}

	if db.Ping() != nil {
		panic(err)
	}

	DB = db
	migrateSql(db)
}

func migrateSql(db *sqlx.DB) {
	migrationsPath := "file://internal/migrations"
	dbName := os.Getenv("DB_NAME")
	driver, err := postgres.WithInstance(db.DB, &postgres.Config{})
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

func StartTransaction(txFunc func(*sqlx.Tx) *customErrors.CustomError) *customErrors.CustomError {
	tx, err := DB.Beginx()
	if err != nil {
		return customErrors.NewInternal(err.Error())
	}

	var txErr *customErrors.CustomError
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		} else if err != nil {
			tx.Rollback()
		} else {
			err = tx.Commit()
		}
	}()

	txErr = txFunc(tx) // Присваиваем значение txErr из функции транзакции
	if txErr != nil {
		tx.Rollback()
		return txErr
	}

	return nil
}

func StartReadOnlyTransaction(txFunc func(*sqlx.Tx) *customErrors.CustomError) *customErrors.CustomError {
	tx, err := DB.BeginTxx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		panic(err)
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		} else if err != nil {
			tx.Rollback()
		} else {
			err = tx.Commit()
		}
	}()

	return txFunc(tx)
}
