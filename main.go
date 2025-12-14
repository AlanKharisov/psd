package main

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	firebase "firebase.google.com/go/v4"
	fbauth "firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"
)

/*
========================
        MODELS
========================
*/

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

type CartItem struct {
	Product  Product
	Quantity int
	Subtotal float64
}

type IndexPageData struct {
	Query       string
	Collections []Product
	NewItems    []Product
	All         []Product
	CartCount   int
	CartTotal   float64
	IsLoggedIn  bool
}

type ProductPageData struct {
	Product    Product
	CartCount  int
	CartTotal  float64
	AvgStars   float64
	IsLoggedIn bool
}

type CartPageData struct {
	Items      []CartItem
	Total      float64
	CartCount  int
	IsLoggedIn bool
}

/*
========================
     SAFE RESPONSE
========================
*/

type trackWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (tw *trackWriter) WriteHeader(code int) {
	if tw.wroteHeader {
		return
	}
	tw.wroteHeader = true
	tw.ResponseWriter.WriteHeader(code)
}

func (tw *trackWriter) Write(b []byte) (int, error) {
	if !tw.wroteHeader {
		tw.WriteHeader(http.StatusOK)
	}
	return tw.ResponseWriter.Write(b)
}

/*
========================
        STATE
========================
*/

var (
	tpl *template.Template

	products      []Product
	productsMutex sync.RWMutex
	nextProductID = 1

	// demo global cart: productID -> qty
	cart      = map[int]int{}
	cartMutex sync.RWMutex

	// rating: 1 time per uid per product
	rated      = map[string]bool{}
	ratedMutex sync.Mutex

	fbAuth *fbauth.Client
)

/*
========================
        MAIN
========================
*/

func main() {
	funcs := template.FuncMap{
		"money": func(v float64) string { return fmt.Sprintf("%.2f", v) },

		// є в наявності?
		"inStock": func(p Product) bool {
			if !p.Limited {
				return true
			}
			return p.Qty > 0
		},
	}

	var err error
	tpl, err = template.New("").Funcs(funcs).ParseGlob("templates/*.html")
	if err != nil {
		log.Fatal("parse templates:", err)
	}

	if err := initFirebaseAdmin(); err != nil {
		log.Fatal("firebase init:", err)
	}

	seedProducts()

	mux := http.NewServeMux()

	// static
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// pages
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/product", productHandler)

	// auth
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.HandleFunc("/sessionLogin", sessionLoginHandler)

	// cart
	mux.HandleFunc("/cart", cartHandler)
	mux.HandleFunc("/cart/add", cartAddHandler)
	mux.HandleFunc("/cart/remove", cartRemoveHandler)

	// rating
	mux.HandleFunc("/rate", rateHandler)

	// admin protected by COOKIE session
	mux.Handle("/admin", requireSession(http.HandlerFunc(adminHandler)))
	mux.Handle("/admin/product", requireSession(http.HandlerFunc(createProductHandler)))

	srv := &http.Server{
		Addr:              ":8010",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Println("http://localhost:8010")
	log.Fatal(srv.ListenAndServe())
}

/*
========================
     FIREBASE ADMIN
========================
*/

func initFirebaseAdmin() error {
	credPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if credPath == "" {
		credPath = "serviceAccountKey.json"
	}
	if _, err := os.Stat(credPath); err != nil {
		return fmt.Errorf("service account json not found: %s", credPath)
	}

	app, err := firebase.NewApp(context.Background(), nil, option.WithCredentialsFile(credPath))
	if err != nil {
		return err
	}

	client, err := app.Auth(context.Background())
	if err != nil {
		return err
	}

	fbAuth = client
	return nil
}

// Create session cookie from Firebase ID token
func sessionLoginHandler(w http.ResponseWriter, r *http.Request) {
	tw := &trackWriter{ResponseWriter: w}

	if r.Method != http.MethodPost {
		http.Error(tw, "POST only", http.StatusMethodNotAllowed)
		return
	}

	body, _ := io.ReadAll(r.Body)
	idToken := strings.TrimSpace(string(body))
	if idToken == "" {
		http.Error(tw, "empty token", http.StatusBadRequest)
		return
	}

	expiresIn := 7 * 24 * time.Hour
	cookie, err := fbAuth.SessionCookie(r.Context(), idToken, expiresIn)
	if err != nil {
		http.Error(tw, "bad token", http.StatusUnauthorized)
		return
	}

	http.SetCookie(tw, &http.Cookie{
		Name:     "session",
		Value:    cookie,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// Secure: true, // enable on HTTPS
		MaxAge: int(expiresIn.Seconds()),
	})

	tw.WriteHeader(http.StatusOK)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoggedIn(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isLoggedIn(r *http.Request) bool {
	c, err := r.Cookie("session")
	if err != nil || c.Value == "" || fbAuth == nil {
		return false
	}
	_, err = fbAuth.VerifySessionCookie(r.Context(), c.Value)
	return err == nil
}

/*
========================
        HELPERS
========================
*/

func normalizePhoto(url string) string {
	url = strings.TrimSpace(url)
	if url == "" {
		return "https://via.placeholder.com/600x400?text=No+Image"
	}
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return url
	}
	// if user entered "600x400?text=Patch"
	if strings.HasPrefix(url, "600x") || strings.HasPrefix(url, "300x") {
		return "https://via.placeholder.com/" + url
	}
	return url
}

func parseDateYYYYMMDD(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func isNew(p Product) bool {
	return time.Now().Before(p.NewUntil)
}

func isHidden(p Product) bool {
	return !p.HideAt.IsZero() && time.Now().After(p.HideAt)
}

func isSoldOutVisible(p Product) bool {
	if !p.Limited {
		return false
	}
	if p.Qty > 0 {
		return false
	}
	if !p.SoldOutUntil.IsZero() {
		return time.Now().Before(p.SoldOutUntil)
	}
	if !p.HideAt.IsZero() {
		return time.Now().Before(p.HideAt)
	}
	return true
}

func avgStars(p Product) float64 {
	if p.StarsCount == 0 {
		return 0
	}
	return float64(p.StarsSum) / float64(p.StarsCount)
}

func addProduct(p Product) {
	productsMutex.Lock()
	defer productsMutex.Unlock()

	p.ID = nextProductID
	nextProductID++

	products = append(products, p)
}

func snapshotProducts() []Product {
	productsMutex.RLock()
	defer productsMutex.RUnlock()
	cp := make([]Product, len(products))
	copy(cp, products)
	return cp
}

func findProductByID(id int) (Product, bool) {
	productsMutex.RLock()
	defer productsMutex.RUnlock()
	for _, p := range products {
		if p.ID == id {
			return p, true
		}
	}
	return Product{}, false
}

func snapshotCart() map[int]int {
	cartMutex.RLock()
	defer cartMutex.RUnlock()
	cp := make(map[int]int, len(cart))
	for k, v := range cart {
		cp[k] = v
	}
	return cp
}

func getCartCount() int {
	cartMutex.RLock()
	defer cartMutex.RUnlock()
	sum := 0
	for _, q := range cart {
		sum += q
	}
	return sum
}

func getCartTotal() float64 {
	c := snapshotCart()
	var total float64
	for id, q := range c {
		p, ok := findProductByID(id)
		if !ok || q <= 0 {
			continue
		}
		total += p.Price * float64(q)
	}
	return total
}

/*
========================
          SEED
========================
*/

func seedProducts() {
	now := time.Now()

	addProduct(Product{
		Photo:       "https://via.placeholder.com/600x400?text=Collection+Set",
		Name:        "Work & Travel Collection Pack",
		StarsSum:    24,
		StarsCount:  6,
		Price:       21000,
		DoublePrice: 18000,
		OldPrice:    23000,
		SalePrice:   21000,
		Category:    "Collections",
		Brand:       "PSDInfo",
		Color:       "Black",
		Size:        "One size",
		Weight:      "—",
		SKU:         "COLL-001",
		Description: "Колекційний набір (демо).",
		CreatedAt:   now,
		NewUntil:    now.AddDate(0, 3, 0),
		Limited:     true,
		Qty:         5,
	})

	addProduct(Product{
		Photo:       "https://via.placeholder.com/600x400?text=Patch",
		Name:        "Patch Work&Travel Dnipro",
		StarsSum:    10,
		StarsCount:  3,
		Price:       400,
		DoublePrice: 300,
		OldPrice:    0,
		SalePrice:   0,
		Category:    "Patches",
		Brand:       "PSDInfo",
		Color:       "White",
		Size:        "M",
		Weight:      "50g",
		SKU:         "PCH-001",
		Description: "Патч (демо).",
		CreatedAt:   now,
		NewUntil:    now.AddDate(0, 3, 0),
		Limited:     true,
		Qty:         10,
	})
}

/*
========================
        HANDLERS
========================
*/

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Якщо вже залогінений — на головну
	if isLoggedIn(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	_ = tpl.ExecuteTemplate(w, "login.html", nil)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	tw := &trackWriter{ResponseWriter: w}

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	lq := strings.ToLower(q)

	all := snapshotProducts()
	matches := make([]Product, 0, len(all))

	for _, p := range all {
		if isHidden(p) {
			continue
		}
		if p.Limited && p.Qty <= 0 && !isSoldOutVisible(p) {
			continue
		}

		if q == "" {
			matches = append(matches, p)
			continue
		}

		hay := strings.ToLower(p.Name + " " + p.SKU + " " + p.Brand + " " + p.Category + " " + p.Color + " " + p.Size)
		if strings.Contains(hay, lq) {
			matches = append(matches, p)
		}
	}

	sort.Slice(matches, func(i, j int) bool { return matches[i].ID > matches[j].ID })

	var collections, newItems, rest []Product
	for _, p := range matches {
		if strings.EqualFold(p.Category, "Collections") || strings.EqualFold(p.Category, "Колекції") {
			collections = append(collections, p)
			continue
		}
		if isNew(p) {
			newItems = append(newItems, p)
			continue
		}
		rest = append(rest, p)
	}

	data := IndexPageData{
		Query:       q,
		Collections: collections,
		NewItems:    newItems,
		All:         rest,
		CartCount:   getCartCount(),
		CartTotal:   getCartTotal(),
		IsLoggedIn:  isLoggedIn(r),
	}

	if err := tpl.ExecuteTemplate(tw, "index.html", data); err != nil {
		log.Println("render index:", err)
		if !tw.wroteHeader {
			http.Error(tw, "template error", http.StatusInternalServerError)
		}
		return
	}
}

func productHandler(w http.ResponseWriter, r *http.Request) {
	tw := &trackWriter{ResponseWriter: w}

	id, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil || id <= 0 {
		http.NotFound(tw, r)
		return
	}

	p, ok := findProductByID(id)
	if !ok || isHidden(p) {
		http.NotFound(tw, r)
		return
	}
	if p.Limited && p.Qty <= 0 && !isSoldOutVisible(p) {
		http.NotFound(tw, r)
		return
	}

	data := ProductPageData{
		Product:    p,
		CartCount:  getCartCount(),
		CartTotal:  getCartTotal(),
		AvgStars:   avgStars(p),
		IsLoggedIn: isLoggedIn(r),
	}

	if err := tpl.ExecuteTemplate(tw, "product.html", data); err != nil {
		log.Println("render product:", err)
		if !tw.wroteHeader {
			http.Error(tw, "template error", http.StatusInternalServerError)
		}
		return
	}
}

func cartHandler(w http.ResponseWriter, r *http.Request) {
	tw := &trackWriter{ResponseWriter: w}

	c := snapshotCart()

	var items []CartItem
	var total float64

	for id, q := range c {
		p, ok := findProductByID(id)
		if !ok || q <= 0 {
			continue
		}
		sub := p.Price * float64(q)
		items = append(items, CartItem{Product: p, Quantity: q, Subtotal: sub})
		total += sub
	}

	data := CartPageData{
		Items:      items,
		Total:      total,
		CartCount:  getCartCount(),
		IsLoggedIn: isLoggedIn(r),
	}

	if err := tpl.ExecuteTemplate(tw, "cart.html", data); err != nil {
		log.Println("render cart:", err)
		if !tw.wroteHeader {
			http.Error(tw, "template error", http.StatusInternalServerError)
		}
		return
	}
}

func cartAddHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()

	id, _ := strconv.Atoi(r.FormValue("id"))
	if id <= 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	p, ok := findProductByID(id)
	if !ok || isHidden(p) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// якщо limited і qty 0 — не дозволяємо
	if p.Limited && p.Qty <= 0 {
		back := r.FormValue("redirect_to")
		if back == "" {
			back = "/product?id=" + strconv.Itoa(id)
		}
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}

	// резерв: зменшуємо qty
	if p.Limited && p.Qty > 0 {
		productsMutex.Lock()
		for i := range products {
			if products[i].ID == id && products[i].Qty > 0 {
				products[i].Qty--
				break
			}
		}
		productsMutex.Unlock()
	}

	cartMutex.Lock()
	cart[id]++
	cartMutex.Unlock()

	back := r.FormValue("redirect_to")
	if back == "" {
		back = "/"
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func cartRemoveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/cart", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()

	id, _ := strconv.Atoi(r.FormValue("id"))
	if id <= 0 {
		http.Redirect(w, r, "/cart", http.StatusSeeOther)
		return
	}

	cartMutex.Lock()
	delete(cart, id)
	cartMutex.Unlock()

	http.Redirect(w, r, "/cart", http.StatusSeeOther)
}

func rateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// потрібен логін (session cookie)
	c, err := r.Cookie("session")
	if err != nil || c.Value == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	tok, err := fbAuth.VerifySessionCookie(r.Context(), c.Value)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	_ = r.ParseForm()
	id, _ := strconv.Atoi(r.FormValue("id"))
	star, _ := strconv.Atoi(r.FormValue("star"))

	if id <= 0 || star < 1 || star > 5 {
		http.Redirect(w, r, "/product?id="+strconv.Itoa(id), http.StatusSeeOther)
		return
	}

	key := tok.UID + ":" + strconv.Itoa(id)

	ratedMutex.Lock()
	if rated[key] {
		ratedMutex.Unlock()
		http.Redirect(w, r, "/product?id="+strconv.Itoa(id), http.StatusSeeOther)
		return
	}
	rated[key] = true
	ratedMutex.Unlock()

	productsMutex.Lock()
	for i := range products {
		if products[i].ID == id {
			products[i].StarsSum += star
			products[i].StarsCount++
			break
		}
	}
	productsMutex.Unlock()

	http.Redirect(w, r, "/product?id="+strconv.Itoa(id), http.StatusSeeOther)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	tw := &trackWriter{ResponseWriter: w}

	all := snapshotProducts()
	if err := tpl.ExecuteTemplate(tw, "admin.html", all); err != nil {
		log.Println("render admin:", err)
		if !tw.wroteHeader {
			http.Error(tw, "template error", http.StatusInternalServerError)
		}
		return
	}
}

func createProductHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()

	now := time.Now()

	price, _ := strconv.ParseFloat(strings.TrimSpace(r.FormValue("price")), 64)
	doublePrice, _ := strconv.ParseFloat(strings.TrimSpace(r.FormValue("double_price")), 64)
	oldPrice, _ := strconv.ParseFloat(strings.TrimSpace(r.FormValue("old_price")), 64)
	salePrice, _ := strconv.ParseFloat(strings.TrimSpace(r.FormValue("sale_price")), 64)

	qty, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("qty")))

	p := Product{
		Photo:       normalizePhoto(r.FormValue("photo")),
		Name:        strings.TrimSpace(r.FormValue("name")),
		SKU:         strings.TrimSpace(r.FormValue("sku")),
		Brand:       strings.TrimSpace(r.FormValue("brand")),
		Category:    strings.TrimSpace(r.FormValue("category")),
		Color:       strings.TrimSpace(r.FormValue("color")),
		Size:        strings.TrimSpace(r.FormValue("size")),
		Weight:      strings.TrimSpace(r.FormValue("weight")),
		Description: strings.TrimSpace(r.FormValue("description")),

		Price:       price,
		DoublePrice: doublePrice,
		OldPrice:    oldPrice,
		SalePrice:   salePrice,

		Limited:      r.FormValue("limited") == "on",
		Qty:          qty,
		SoldOutUntil: parseDateYYYYMMDD(r.FormValue("sold_out_until")),
		HideAt:       parseDateYYYYMMDD(r.FormValue("hide_at")),

		CreatedAt: now,
		NewUntil:  now.AddDate(0, 3, 0),
	}

	addProduct(p)

	// після створення — на головну, щоб одразу побачити
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
