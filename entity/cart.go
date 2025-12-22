package entity

type CartItem struct {
	Product  Product
	Quantity int
	Subtotal float64
}

type CartPageData struct {
	Items      []CartItem
	Total      float64
	CartCount  int
	IsLoggedIn bool
}
