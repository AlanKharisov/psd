package entity

import "time"

type Product struct {
	ID    int
	Photo string
	Name  string

	// rating
	StarsSum   int
	StarsCount int

	// prices
	Price       float64
	DoublePrice float64
	OldPrice    float64
	SalePrice   float64

	// attributes
	Category string
	Brand    string
	Color    string
	Size     string
	Weight   string
	SKU      string

	Description string

	// time flags
	CreatedAt time.Time
	NewUntil  time.Time // auto: CreatedAt + 3 months

	// limited stock / hide logic
	Limited      bool
	Qty          int
	SoldOutUntil time.Time // show "sold out" till this date
	HideAt       time.Time // hide product after this date
}
