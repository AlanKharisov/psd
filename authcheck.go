package main

import (
	"database/sql"
	"emil/repository"
	_ "github.com/go-sql-driver/mysql"
	"log"
)

func main() {
	dsn := "root:21Alan06@tcp(localhost:3306)/emil?parseTime=true&charset=utf8mb4&loc=Local"
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("DB open error: %v", err)
	}
	defer db.Close()
	authRepo := repository.NewAuth(db)
	res, err := authRepo.Login("admin", "0001")
	if err != nil {
		log.Fatalf("Auth login error: %v", err)
	}
	log.Printf("Auth login: %v", res)
}
