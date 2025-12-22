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

	"cloud.google.com/go/firestore"
	firebase "firebase.google.com/go/v4"
	fbauth "firebase.google.com/go/v4/auth"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// ====== МОДЕЛІ ДЛЯ ШОПУ ======

type Product struct {
	ID    string
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
	NewUntil  time.Time // CreatedAt + 3 місяці

	// limited stock / hide logic
	Limited      bool
	Qty          int
	SoldOutUntil time.Time // показувати "продано" до цієї дати
	HideAt       time.Time // сховати після цієї дати
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

// Firestore shape (як зберігає адмінка)
type productDoc struct {
	Name         string    `firestore:"name"`
	SKU          string    `firestore:"sku"`
	Brand        string    `firestore:"brand"`
	Category     string    `firestore:"category"`
	Photo        string    `firestore:"photo"`
	Color        string    `firestore:"color"`
	Size         string    `firestore:"size"`
	Weight       string    `firestore:"weight"`
	Qty          int       `firestore:"qty"`
	Price        float64   `firestore:"price"`
	DoublePrice  float64   `firestore:"doublePrice"`
	OldPrice     float64   `firestore:"oldPrice"`
	SalePrice    float64   `firestore:"salePrice"`
	Limited      bool      `firestore:"limited"`
	SoldOutUntil string    `firestore:"soldOutUntil"` // "YYYY-MM-DD" або ""
	HideAt       string    `firestore:"hideAt"`       // "YYYY-MM-DD" або ""
	Description  string    `firestore:"description"`
	CreatedAt    time.Time `firestore:"createdAt"`

	StarsSum   int `firestore:"starsSum"`
	StarsCount int `firestore:"starsCount"`
}

// ====== Трекер для коректного статус-коду ======

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

// ====== Глобальні змінні ======

var (
	tpl *template.Template

	// корзина: productID (doc.id) -> qty
	cart      = map[string]int{}
	cartMutex sync.RWMutex

	// рейтинги: uid:productID -> вже голосував
	rated      = map[string]bool{}
	ratedMutex sync.Mutex

	fbAuth   *fbauth.Client
	fsClient *firestore.Client
)

// ====== MAIN ======

func main() {
	funcs := template.FuncMap{
		"money": func(v float64) string { return fmt.Sprintf("%.2f", v) },

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
	defer fsClient.Close()

	// Микс для магазина
	shopMux := newShopMux()

	// Микс для адмінки
	adminMux := newAdminMux()

	// ROOT mux, який розрулює по домену (Host)
	rootMux := http.NewServeMux()
	rootMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host := r.Host

		// admin.world-of-photo.com (з портом або без)
		if strings.HasPrefix(host, "admin.world-of-photo.com") ||
			strings.HasPrefix(host, "admin.world-of-photo.com:") {
			adminMux.ServeHTTP(w, r)
			return
		}

		// Все інше (включно з p.world-of-photo.com, localhost:8010 і т.д.) → магазин
		shopMux.ServeHTTP(w, r)
	})

	srv := &http.Server{
		Addr:              ":8010",
		Handler:           rootMux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Println("Listening on :8010 (shop + admin by Host header)")
	log.Fatal(srv.ListenAndServe())
}

// ====== MUX для магазина ======

func newShopMux() *http.ServeMux {
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

	return mux
}

// ====== MUX для адмінки ======

func newAdminMux() *http.ServeMux {
	mux := http.NewServeMux()

	// статика для адмінки (та ж сама папка)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// головна сторінка адмінки
	mux.HandleFunc("/admin", adminHandler)

	// root цього сабдомену -> /admin
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusFound)
	})

	return mux
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	if err := tpl.ExecuteTemplate(w, "admin.html", nil); err != nil {
		log.Println("admin template error:", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
}

// ====== Firebase Admin / Firestore ======

func initFirebaseAdmin() error {
	credPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if credPath == "" {
		credPath = "serviceAccountKey.json"
	}
	if _, err := os.Stat(credPath); err != nil {
		return fmt.Errorf("service account json not found: %s", credPath)
	}

	ctx := context.Background()

	app, err := firebase.NewApp(ctx, nil, option.WithCredentialsFile(credPath))
	if err != nil {
		return err
	}

	client, err := app.Auth(ctx)
	if err != nil {
		return err
	}
	fbAuth = client

	fs, err := app.Firestore(ctx)
	if err != nil {
		return err
	}
	fsClient = fs

	return nil
}

// ====== Допоміжні ======

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
		// Secure: true,
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

func isLoggedIn(r *http.Request) bool {
	if fbAuth == nil {
		return false
	}
	c, err := r.Cookie("session")
	if err != nil || c.Value == "" {
		return false
	}
	_, err = fbAuth.VerifySessionCookie(r.Context(), c.Value)
	return err == nil
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
	return !p.NewUntil.IsZero() && time.Now().Before(p.NewUntil)
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

// ====== Робота з Firestore (товари) ======

func productFromDoc(doc *firestore.DocumentSnapshot) (Product, error) {
	var pd productDoc
	if err := doc.DataTo(&pd); err != nil {
		return Product{}, err
	}

	created := pd.CreatedAt
	var newUntil time.Time
	if !created.IsZero() {
		newUntil = created.AddDate(0, 3, 0)
	}

	return Product{
		ID:    doc.Ref.ID,
		Photo: pd.Photo,
		Name:  pd.Name,

		StarsSum:   pd.StarsSum,
		StarsCount: pd.StarsCount,

		Price:       pd.Price,
		DoublePrice: pd.DoublePrice,
		OldPrice:    pd.OldPrice,
		SalePrice:   pd.SalePrice,

		Category: pd.Category,
		Brand:    pd.Brand,
		Color:    pd.Color,
		Size:     pd.Size,
		Weight:   pd.Weight,
		SKU:      pd.SKU,

		Description: pd.Description,

		CreatedAt:    created,
		NewUntil:     newUntil,
		Limited:      pd.Limited,
		Qty:          pd.Qty,
		SoldOutUntil: parseDateYYYYMMDD(pd.SoldOutUntil),
		HideAt:       parseDateYYYYMMDD(pd.HideAt),
	}, nil
}

func fetchAllProducts(ctx context.Context) ([]Product, error) {
	iter := fsClient.Collection("products").OrderBy("createdAt", firestore.Desc).Documents(ctx)
	defer iter.Stop()

	var res []Product
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		p, err := productFromDoc(doc)
		if err != nil {
			log.Println("productFromDoc error:", err)
			continue
		}
		res = append(res, p)
	}
	return res, nil
}

func fetchProductByID(ctx context.Context, id string) (Product, error) {
	doc, err := fsClient.Collection("products").Doc(id).Get(ctx)
	if err != nil {
		return Product{}, err
	}
	return productFromDoc(doc)
}

// ====== Корзина ======

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
	cartMutex.RLock()
	defer cartMutex.RUnlock()

	var total float64
	for id, q := range cart {
		if q <= 0 {
			continue
		}
		p, err := fetchProductByID(context.Background(), id)
		if err != nil || isHidden(p) {
			continue
		}
		total += p.Price * float64(q)
	}
	return total
}

// ====== Хендлери сторінок ======

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if isLoggedIn(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	_ = tpl.ExecuteTemplate(w, "login.html", nil)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	tw := &trackWriter{ResponseWriter: w}

	all, err := fetchAllProducts(r.Context())
	if err != nil {
		log.Println("fetchAllProducts:", err)
		http.Error(tw, "DB error", http.StatusInternalServerError)
		return
	}

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	lq := strings.ToLower(q)

	var matches []Product
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

	// сортуємо за CreatedAt (новіші зверху)
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].CreatedAt.After(matches[j].CreatedAt)
	})

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

	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		http.NotFound(tw, r)
		return
	}

	p, err := fetchProductByID(r.Context(), id)
	if err != nil || isHidden(p) {
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

	cartMutex.RLock()
	snap := make(map[string]int, len(cart))
	for k, v := range cart {
		snap[k] = v
	}
	cartMutex.RUnlock()

	var items []CartItem
	var total float64

	for id, q := range snap {
		if q <= 0 {
			continue
		}
		p, err := fetchProductByID(r.Context(), id)
		if err != nil || isHidden(p) {
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

	id := strings.TrimSpace(r.FormValue("id"))
	if id == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	p, err := fetchProductByID(r.Context(), id)
	if err != nil || isHidden(p) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if p.Limited && p.Qty <= 0 {
		back := r.FormValue("redirect_to")
		if back == "" {
			back = "/product?id=" + id
		}
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}

	// ТУТ ми не змінюємо Qty у Firestore, тільки візуально додаємо в корзину
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

	id := strings.TrimSpace(r.FormValue("id"))
	if id == "" {
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
	id := strings.TrimSpace(r.FormValue("id"))
	star, _ := strconv.Atoi(r.FormValue("star"))

	if id == "" || star < 1 || star > 5 {
		http.Redirect(w, r, "/product?id="+id, http.StatusSeeOther)
		return
	}

	key := tok.UID + ":" + id

	ratedMutex.Lock()
	if rated[key] {
		ratedMutex.Unlock()
		http.Redirect(w, r, "/product?id="+id, http.StatusSeeOther)
		return
	}
	rated[key] = true
	ratedMutex.Unlock()

	// оновлюємо в Firestore
	_, err = fsClient.Collection("products").Doc(id).Update(r.Context(), []firestore.Update{
		{Path: "starsSum", Value: firestore.Increment(int64(star))},
		{Path: "starsCount", Value: firestore.Increment(int64(1))},
	})
	if err != nil {
		log.Println("rate update error:", err)
	}

	http.Redirect(w, r, "/product?id="+id, http.StatusSeeOther)
}
