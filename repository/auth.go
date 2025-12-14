package repository

import (
	"database/sql"
	"emil/entity"
)

type Auth struct {
	db *sql.DB
}

func NewAuth(db *sql.DB) *Auth {
	return &Auth{db: db}
}

func (a *Auth) Login(username, password string) (bool, error) {
	var user entity.User

	err := a.db.QueryRow(
		"SELECT id, name, username, password FROM users WHERE username = ?",
		username,
	).Scan(
		&user.ID,
		&user.Name,
		&user.Username,
		&user.Password,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil // користувача не знайдено
		}
		return false, err
	}

	return user.Password == password, nil
}
