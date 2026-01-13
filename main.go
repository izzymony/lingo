package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

func init() {
	if len(jwtSecret) == 0 {
		jwtSecret = []byte("your-secret-key-change-in-production")
	}
}

// Models
type Car struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Make        string             `json:"make" bson:"make"`
	Model       string             `json:"model" bson:"model"`
	Year        int                `json:"year" bson:"year"`
	Price       float64            `json:"price" bson:"price"`
	Mileage     int                `json:"mileage" bson:"mileage"`
	Color       string             `json:"color" bson:"color"`
	Description string             `json:"description" bson:"description"`
	ImageURL    string             `json:"image_url" bson:"image_url"`
	Status      string             `json:"status" bson:"status"` // available, sold, reserved
	CreatedAt   time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at" bson:"updated_at"`
}

type User struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Email     string             `json:"email" bson:"email"`
	Password  string             `json:"-" bson:"password"`
	Name      string             `json:"name" bson:"name"`
	Phone     string             `json:"phone" bson:"phone"`
	Role      string             `json:"role" bson:"role"` // admin, customer
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
}

type Order struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	UserID    primitive.ObjectID `json:"user_id" bson:"user_id"`
	CarID     primitive.ObjectID `json:"car_id" bson:"car_id"`
	Status    string             `json:"status" bson:"status"` // pending, completed, cancelled
	Total     float64            `json:"total" bson:"total"`
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
	Phone    string `json:"phone"`
}

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Page       int         `json:"page"`
	PageSize   int         `json:"page_size"`
	Total      int64       `json:"total"`
	TotalPages int         `json:"total_pages"`
}

// Database
type Database struct {
	client *mongo.Client
	cars   *mongo.Collection
	users  *mongo.Collection
	orders *mongo.Collection
}

var db *Database

// Initialize MongoDB connection
func initDB() (*Database, error) {
	mongoURI := os.Getenv("MONGODB_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %v", err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %v", err)
	}

	dbName := os.Getenv("DB_NAME")
	if dbName == "" {
		dbName = "car_ecommerce"
	}

	database := client.Database(dbName)
	carsCollection := database.Collection("cars")
	usersCollection := database.Collection("users")
	ordersCollection := database.Collection("orders")

	// Create indexes
	_, err = carsCollection.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "status", Value: 1}}},
		{Keys: bson.D{{Key: "make", Value: 1}}},
		{Keys: bson.D{{Key: "price", Value: 1}}},
	})
	if err != nil {
		log.Printf("Warning: failed to create car indexes: %v", err)
	}

	_, err = usersCollection.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		log.Printf("Warning: failed to create user index: %v", err)
	}

	log.Println("Connected to MongoDB successfully")

	return &Database{
		client: client,
		cars:   carsCollection,
		users:  usersCollection,
		orders: ordersCollection,
	}, nil
}

func (d *Database) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return d.client.Disconnect(ctx)
}

// Helper functions
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateToken(userID, email, role string) (string, error) {
	claims := Claims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func getPaginationParams(r *http.Request) (int, int) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	return page, pageSize
}

// Auth Handlers
func register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" || req.Name == "" {
		respondError(w, http.StatusBadRequest, "Email, password, and name are required")
		return
	}

	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	user := User{
		ID:        primitive.NewObjectID(),
		Email:     req.Email,
		Password:  hashedPassword,
		Name:      req.Name,
		Phone:     req.Phone,
		Role:      "customer",
		CreatedAt: time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = db.users.InsertOne(ctx, user)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			respondError(w, http.StatusConflict, "Email already exists")
			return
		}
		respondError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	token, err := generateToken(user.ID.Hex(), user.Email, user.Role)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"user":  user,
		"token": token,
	})
}

func login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err := db.users.FindOne(ctx, bson.M{"email": req.Email}).Decode(&user)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	if !checkPassword(req.Password, user.Password) {
		respondError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	token, err := generateToken(user.ID.Hex(), user.Email, user.Role)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"user":  user,
		"token": token,
	})
}

// Car Handlers with advanced filters and pagination
func getCars(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	page, pageSize := getPaginationParams(r)
	skip := (page - 1) * pageSize

	// Build filter
	filter := bson.M{}
	
	if status := r.URL.Query().Get("status"); status != "" {
		filter["status"] = status
	}
	
	if make := r.URL.Query().Get("make"); make != "" {
		filter["make"] = bson.M{"$regex": make, "$options": "i"}
	}
	
	if model := r.URL.Query().Get("model"); model != "" {
		filter["model"] = bson.M{"$regex": model, "$options": "i"}
	}
	
	if minPrice := r.URL.Query().Get("min_price"); minPrice != "" {
		price, _ := strconv.ParseFloat(minPrice, 64)
		if filter["price"] == nil {
			filter["price"] = bson.M{}
		}
		filter["price"].(bson.M)["$gte"] = price
	}
	
	if maxPrice := r.URL.Query().Get("max_price"); maxPrice != "" {
		price, _ := strconv.ParseFloat(maxPrice, 64)
		if filter["price"] == nil {
			filter["price"] = bson.M{}
		}
		filter["price"].(bson.M)["$lte"] = price
	}
	
	if year := r.URL.Query().Get("year"); year != "" {
		y, _ := strconv.Atoi(year)
		filter["year"] = y
	}

	// Sort options
	sortField := r.URL.Query().Get("sort_by")
	sortOrder := 1
	if r.URL.Query().Get("sort_order") == "desc" {
		sortOrder = -1
	}
	if sortField == "" {
		sortField = "created_at"
		sortOrder = -1
	}

	opts := options.Find().
		SetSkip(int64(skip)).
		SetLimit(int64(pageSize)).
		SetSort(bson.D{{Key: sortField, Value: sortOrder}})

	total, err := db.cars.CountDocuments(ctx, filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to count cars")
		return
	}

	cursor, err := db.cars.Find(ctx, filter, opts)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch cars")
		return
	}
	defer cursor.Close(ctx)

	var cars []Car
	if err := cursor.All(ctx, &cars); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to decode cars")
		return
	}

	if cars == nil {
		cars = []Car{}
	}

	totalPages := int(total) / pageSize
	if int(total)%pageSize != 0 {
		totalPages++
	}

	respondJSON(w, http.StatusOK, PaginatedResponse{
		Data:       cars,
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		TotalPages: totalPages,
	})
}

func getCar(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := primitive.ObjectIDFromHex(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid car ID")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var car Car
	err = db.cars.FindOne(ctx, bson.M{"_id": id}).Decode(&car)
	if err == mongo.ErrNoDocuments {
		respondError(w, http.StatusNotFound, "Car not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch car")
		return
	}

	respondJSON(w, http.StatusOK, car)
}

func createCar(w http.ResponseWriter, r *http.Request) {
	var car Car
	if err := json.NewDecoder(r.Body).Decode(&car); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	car.ID = primitive.NewObjectID()
	car.CreatedAt = time.Now()
	car.UpdatedAt = time.Now()
	if car.Status == "" {
		car.Status = "available"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := db.cars.InsertOne(ctx, car)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create car")
		return
	}

	respondJSON(w, http.StatusCreated, car)
}

func updateCar(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := primitive.ObjectIDFromHex(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid car ID")
		return
	}

	var updateData Car
	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	updateData.UpdatedAt = time.Now()
	update := bson.M{
		"$set": bson.M{
			"make":        updateData.Make,
			"model":       updateData.Model,
			"year":        updateData.Year,
			"price":       updateData.Price,
			"mileage":     updateData.Mileage,
			"color":       updateData.Color,
			"description": updateData.Description,
			"image_url":   updateData.ImageURL,
			"status":      updateData.Status,
			"updated_at":  updateData.UpdatedAt,
		},
	}

	result, err := db.cars.UpdateOne(ctx, bson.M{"_id": id}, update)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update car")
		return
	}

	if result.MatchedCount == 0 {
		respondError(w, http.StatusNotFound, "Car not found")
		return
	}

	updateData.ID = id
	respondJSON(w, http.StatusOK, updateData)
}

func deleteCar(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := primitive.ObjectIDFromHex(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid car ID")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := db.cars.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete car")
		return
	}

	if result.DeletedCount == 0 {
		respondError(w, http.StatusNotFound, "Car not found")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"message": "Car deleted successfully"})
}

// Order Handlers with transactions
func createOrder(w http.ResponseWriter, r *http.Request) {
	var order Order
	if err := json.NewDecoder(r.Body).Decode(&order); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start a session for transaction
	session, err := db.client.StartSession()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to start transaction")
		return
	}
	defer session.EndSession(ctx)

	// Execute transaction
	_, err = session.WithTransaction(ctx, func(sessCtx mongo.SessionContext) (interface{}, error) {
		// Verify user exists
		var user User
		err := db.users.FindOne(sessCtx, bson.M{"_id": order.UserID}).Decode(&user)
		if err != nil {
			return nil, fmt.Errorf("user not found")
		}

		// Verify car exists and is available
		var car Car
		err = db.cars.FindOne(sessCtx, bson.M{"_id": order.CarID}).Decode(&car)
		if err != nil {
			return nil, fmt.Errorf("car not found")
		}

		if car.Status != "available" {
			return nil, fmt.Errorf("car is not available")
		}

		// Create order
		order.ID = primitive.NewObjectID()
		order.CreatedAt = time.Now()
		order.Status = "pending"
		order.Total = car.Price

		_, err = db.orders.InsertOne(sessCtx, order)
		if err != nil {
			return nil, fmt.Errorf("failed to create order")
		}

		// Update car status to reserved
		_, err = db.cars.UpdateOne(
			sessCtx,
			bson.M{"_id": order.CarID},
			bson.M{"$set": bson.M{"status": "reserved", "updated_at": time.Now()}},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to update car status")
		}

		return nil, nil
	})

	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, order)
}

func getOrders(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	page, pageSize := getPaginationParams(r)
	skip := (page - 1) * pageSize

	filter := bson.M{}
	if userID := r.URL.Query().Get("user_id"); userID != "" {
		id, err := primitive.ObjectIDFromHex(userID)
		if err == nil {
			filter["user_id"] = id
		}
	}

	opts := options.Find().
		SetSkip(int64(skip)).
		SetLimit(int64(pageSize)).
		SetSort(bson.D{{Key: "created_at", Value: -1}})

	total, _ := db.orders.CountDocuments(ctx, filter)

	cursor, err := db.orders.Find(ctx, filter, opts)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch orders")
		return
	}
	defer cursor.Close(ctx)

	var orders []Order
	if err := cursor.All(ctx, &orders); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to decode orders")
		return
	}

	if orders == nil {
		orders = []Order{}
	}

	totalPages := int(total) / pageSize
	if int(total)%pageSize != 0 {
		totalPages++
	}

	respondJSON(w, http.StatusOK, PaginatedResponse{
		Data:       orders,
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		TotalPages: totalPages,
	})
}

func getOrder(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := primitive.ObjectIDFromHex(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid order ID")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var order Order
	err = db.orders.FindOne(ctx, bson.M{"_id": id}).Decode(&order)
	if err == mongo.ErrNoDocuments {
		respondError(w, http.StatusNotFound, "Order not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch order")
		return
	}

	respondJSON(w, http.StatusOK, order)
}

// Middleware
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			respondError(w, http.StatusUnauthorized, "Authorization header required")
			return
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			respondError(w, http.StatusUnauthorized, "Invalid token")
			return
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func adminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := r.Context().Value("claims").(*Claims)
		if claims.Role != "admin" {
			respondError(w, http.StatusForbidden, "Admin access required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("%s %s", r.Method, r.RequestURI)
		next.ServeHTTP(w, r)
		log.Printf("Completed in %v", time.Since(start))
	})
}

func main() {
	var err error
	db, err = initDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	r := mux.NewRouter()

	// Public routes
	r.HandleFunc("/api/auth/register", register).Methods("POST")
	r.HandleFunc("/api/auth/login", login).Methods("POST")
	r.HandleFunc("/api/cars", getCars).Methods("GET")
	r.HandleFunc("/api/cars/{id}", getCar).Methods("GET")
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
	}).Methods("GET")

	// Protected routes (require authentication)
	protected := r.PathPrefix("/api").Subrouter()
	protected.Use(authMiddleware)
	
	protected.HandleFunc("/users/{id}", getUser).Methods("GET")
	protected.HandleFunc("/orders", createOrder).Methods("POST")
	protected.HandleFunc("/orders", getOrders).Methods("GET")
	protected.HandleFunc("/orders/{id}", getOrder).Methods("GET")

	// Admin routes (require admin role)
	admin := r.PathPrefix("/api/admin").Subrouter()
	admin.Use(authMiddleware)
	admin.Use(adminMiddleware)
	
	admin.HandleFunc("/cars", createCar).Methods("POST")
	admin.HandleFunc("/cars/{id}", updateCar).Methods("PUT")
	admin.HandleFunc("/cars/{id}", deleteCar).Methods("DELETE")

	// Apply global middleware
	r.Use(corsMiddleware)
	r.Use(loggingMiddleware)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("Server starting on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

func getUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := primitive.ObjectIDFromHex(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err = db.users.FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		respondError(w, http.StatusNotFound, "User not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch user")
		return
	}

	respondJSON(w, http.StatusOK, user)
}