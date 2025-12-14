package entity

type User struct {
	ID       int64  `db:"id"`
	Name     string `db:"name"`
	Username string `db:"username"`
	Password string `db:"password"`
}
