package entity

type IndexPageData struct {
	Query       string
	Collections []Product
	NewItems    []Product
	All         []Product
	CartCount   int
	CartTotal   float64
	IsLoggedIn  bool
}
