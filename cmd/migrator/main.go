package main

import (
	"errors"
	"flag"
	"fmt"
	_ "github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/sqlite3"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
	var storagePath, migrationsPath, migrationsTable string

	flag.StringVar(&storagePath, "storagePath", "./storage/sso.db", "Path to the storage path")
	flag.StringVar(&migrationsPath, "migrationsPath", "./migrations", "Path to the migrations folder")
	flag.StringVar(&migrationsTable, "migrationsTable", "", "Name of the migrations table")
	flag.Parse()

	if storagePath == "" || migrationsPath == "" {
		panic("StoragePath and MigrationsPath are required")
	}
	m, err := migrate.New("file://"+migrationsPath, fmt.Sprintf("sqlite3://%s?x-migrations-table=%s", storagePath, migrationsTable))
	if err != nil {
		panic(err)
	}

	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			fmt.Println("No change")
			return
		}
		panic(err)
	}
	fmt.Println("Migrations successfully migrated")
}
