package main

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	firebase "firebase.google.com/go/v4"
	fbauth "firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"
)

type Product struct {
	ID           int
	Photo        string
	Name         string
	Stars        int
	Presence     bool
	Price        float64
	Category     string
	Brand        string
	Color        string
	Size         string
	Weight       string
	SKU          string
	Party        string
	Description  string
	IsNew        bool
	IsCollection bool
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
}

type CartPageData struct {
	Items     []CartItem
	Total     float64
	CartCount int
}

var (
	tpl *template.Template

	products      []Product
	productsMutex sync.RWMutex
	nextProductID = 1

	cart      = map[int]int{}
	cartMutex sync.RWMutex

	fbAuth *fbauth.Client
)

func main() {
	var err error
	tpl, err = template.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatal("parse templates:", err)
	}

	if err := initFirebaseAdmin(); err != nil {
		log.Fatal("firebase init:", err)
	}

	seedProducts()

	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// pages
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logoutHandler)

	// session endpoints
	mux.HandleFunc("/sessionLogin", sessionLoginHandler)

	// cart
	mux.HandleFunc("/cart", cartHandler)
	mux.HandleFunc("/cart/add", cartAddHandler)
	mux.HandleFunc("/cart/remove", cartRemoveHandler)

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

// ===== SESSION (cookie) =====

// создаём cookie "session" по ID token'у
func sessionLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	body, _ := io.ReadAll(r.Body)
	idToken := strings.TrimSpace(string(body))
	if idToken == "" {
		http.Error(w, "empty token", 400)
		return
	}

	// 7 дней (можешь меньше)
	expiresIn := 7 * 24 * time.Hour

	// Firebase Admin создаёт session cookie
	cookie, err := fbAuth.SessionCookie(r.Context(), idToken, expiresIn)
	if err != nil {
		http.Error(w, "bad token", 401)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    cookie,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// Secure: true, // включишь на HTTPS
		MaxAge: int(expiresIn.Seconds()),
	})

	w.WriteHeader(200)
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
		c, err := r.Cookie("session")
		if err != nil || c.Value == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// проверяем session cookie
		_, err = fbAuth.VerifySessionCookie(r.Context(), c.Value)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ===== DATA HELPERS =====

func addProduct(p Product) {
	productsMutex.Lock()
	defer productsMutex.Unlock()
	p.ID = nextProductID
	nextProductID++
	products = append(products, p)
}

func normalizePhoto(url string) string {
	url = strings.TrimSpace(url)
	if url == "" {
		return "https://via.placeholder.com/600x400?text=No+Image"
	}
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return url
	}
	// Если пользователь вставил "600x400?text=Patch" — исправим
	if strings.HasPrefix(url, "600x") || strings.HasPrefix(url, "300x") {
		return "https://via.placeholder.com/" + url
	}
	return url
}

func seedProducts() {
	addProduct(Product{
		Photo:        "https://via.placeholder.com/600x400?text=Collection+Set",
		Name:         "Work & Travel Collection Pack",
		Brand:        "PSDInfo",
		Category:     "Collections",
		SKU:          "COLL-001",
		Price:        21000,
		Presence:     true,
		IsNew:        true,
		IsCollection: true,
	})
	addProduct(Product{
		Photo:    "https://via.placeholder.com/600x400?text=Patch",
		Name:     "Patch Work&Travel Dnipro",
		Brand:    "PSDInfo",
		Category: "Patches",
		SKU:      "PCH-001",
		Price:    400,
		Presence: true,
	})
}

func snapshotProducts() []Product {
	productsMutex.RLock()
	defer productsMutex.RUnlock()
	cp := make([]Product, len(products))
	copy(cp, products)
	return cp
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

// ===== HANDLERS =====

func loginHandler(w http.ResponseWriter, r *http.Request) {
	_ = tpl.ExecuteTemplate(w, "login.html", nil)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	lq := strings.ToLower(q)

	all := snapshotProducts()
	matches := make([]Product, 0, len(all))
	for _, p := range all {
		if q == "" {
			matches = append(matches, p)
			continue
		}
		hay := strings.ToLower(p.Name + " " + p.SKU + " " + p.Brand + " " + p.Category + " " + p.Color)
		if strings.Contains(hay, lq) {
			matches = append(matches, p)
		}
	}

	var collections, newItems, rest []Product
	for _, p := range matches {
		if p.IsCollection {
			collections = append(collections, p)
		} else if p.IsNew {
			newItems = append(newItems, p)
		} else {
			rest = append(rest, p)
		}
	}

	data := IndexPageData{
		Query:       q,
		Collections: collections,
		NewItems:    newItems,
		All:         rest,
		CartCount:   getCartCount(),
	}
	_ = tpl.ExecuteTemplate(w, "index.html", data)
}

func cartHandler(w http.ResponseWriter, r *http.Request) {
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

	data := CartPageData{Items: items, Total: total, CartCount: getCartCount()}
	_ = tpl.ExecuteTemplate(w, "cart.html", data)
}

func cartAddHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	id, _ := strconv.Atoi(r.FormValue("id"))
	if _, ok := findProductByID(id); !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
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

	cartMutex.Lock()
	delete(cart, id)
	cartMutex.Unlock()

	http.Redirect(w, r, "/cart", http.StatusSeeOther)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	all := snapshotProducts()
	_ = tpl.ExecuteTemplate(w, "admin.html", all)
}

func createProductHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()

	price, _ := strconv.ParseFloat(strings.TrimSpace(r.FormValue("price")), 64)
	stars, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("stars")))

	addProduct(Product{
		Photo:        normalizePhoto(r.FormValue("photo")),
		Name:         strings.TrimSpace(r.FormValue("name")),
		Brand:        strings.TrimSpace(r.FormValue("brand")),
		Category:     strings.TrimSpace(r.FormValue("category")),
		SKU:          strings.TrimSpace(r.FormValue("sku")),
		Description:  strings.TrimSpace(r.FormValue("description")),
		Price:        price,
		Stars:        stars,
		Presence:     r.FormValue("presence") == "on",
		IsNew:        r.FormValue("is_new") == "on",
		IsCollection: r.FormValue("is_collection") == "on",
	})

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
