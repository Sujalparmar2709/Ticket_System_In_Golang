package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	statusOpen       = "open"
	statusInProgress = "in_progress"
	statusClosed     = "closed"
)

type User struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name,omitempty"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

type Ticket struct {
	ID          int64     `json:"id"`
	UserID      int64     `json:"user_id"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type store struct {
	mu           sync.RWMutex
	nextUserID   int64
	nextTicketID int64
	usersByID    map[int64]*User
	usersByEmail map[string]int64
	ticketsByID  map[int64]*Ticket
}

type server struct {
	store     *store
	jwtSecret []byte
}

type jwtClaims struct {
	UserID int64  `json:"user_id"`
	Email  string `json:"email"`
	Exp    int64  `json:"exp"`
	Iat    int64  `json:"iat"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	addr := ":" + port
	log.Printf("ticket system listening on %s", addr)
	if err := http.ListenAndServe(addr, loggingMiddleware(newServer(os.Getenv("JWT_SECRET")).routes())); err != nil {
		log.Fatal(err)
	}
}

func newServer(secret string) *server {
	if secret == "" {
		secret = "dev-secret"
	}
	return &server{
		store: &store{
			usersByID:    make(map[int64]*User),
			usersByEmail: make(map[string]int64),
			ticketsByID:  make(map[int64]*Ticket),
		},
		jwtSecret: []byte(secret),
	}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleHome)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/auth/register", s.handleRegister)
	mux.HandleFunc("/auth/login", s.handleLogin)
	mux.HandleFunc("/tickets", s.handleTickets)
	mux.HandleFunc("/tickets/", s.handleTicketByID)
	return mux
}

func (s *server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		methodNotAllowed(w)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"service": "ticket-system",
		"health":  "/health",
	})
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}

	payload, err := readJSONObject(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	email := normalizeString(firstString(payload, "email", "username"))
	password := firstString(payload, "password")
	name := firstString(payload, "name", "full_name", "username")
	if email == "" || password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	hash, err := hashPassword(password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to hash password")
		return
	}

	user, err := s.store.createUser(name, email, hash)
	if err != nil {
		if errors.Is(err, errUserExists) {
			writeError(w, http.StatusConflict, "user already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "unable to register user")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         user.ID,
		"name":       user.Name,
		"email":      user.Email,
		"created_at": user.CreatedAt,
	})
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}

	payload, err := readJSONObject(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	email := normalizeString(firstString(payload, "email", "username"))
	password := firstString(payload, "password")
	if email == "" || password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	user, ok := s.store.getUserByEmail(email)
	if !ok || !verifyPassword(password, user.PasswordHash) {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token, err := createToken(s.jwtSecret, user.ID, user.Email, 24*time.Hour)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unable to create token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"token": token})
}

func (s *server) handleTickets(w http.ResponseWriter, r *http.Request) {
	user, ok := s.authorize(w, r)
	if !ok {
		return
	}

	switch r.Method {
	case http.MethodPost:
		payload, err := readJSONObject(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		title := firstString(payload, "title", "subject")
		description := firstString(payload, "description", "details", "body")
		if strings.TrimSpace(title) == "" {
			writeError(w, http.StatusBadRequest, "title is required")
			return
		}

		ticket := s.store.createTicket(user.ID, strings.TrimSpace(title), strings.TrimSpace(description))
		writeJSON(w, http.StatusCreated, ticket)
	case http.MethodGet:
		tickets := s.store.listTicketsByUser(user.ID)
		writeJSON(w, http.StatusOK, tickets)
	default:
		methodNotAllowed(w, http.MethodPost, http.MethodGet)
	}
}

func (s *server) handleTicketByID(w http.ResponseWriter, r *http.Request) {
	user, ok := s.authorize(w, r)
	if !ok {
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/tickets/")
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "ticket not found")
		return
	}

	ticketID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || ticketID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid ticket id")
		return
	}

	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		ticket, found := s.store.getTicket(ticketID)
		if !found || ticket.UserID != user.ID {
			writeError(w, http.StatusNotFound, "ticket not found")
			return
		}
		writeJSON(w, http.StatusOK, ticket)
	case len(parts) == 2 && parts[1] == "status" && r.Method == http.MethodPatch:
		ticket, found := s.store.getTicket(ticketID)
		if !found || ticket.UserID != user.ID {
			writeError(w, http.StatusNotFound, "ticket not found")
			return
		}

		payload, err := readJSONObject(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		newStatus := strings.TrimSpace(firstString(payload, "status"))
		updated, err := s.store.updateTicketStatus(ticketID, newStatus)
		if err != nil {
			if errors.Is(err, errInvalidStatus) || errors.Is(err, errInvalidTransition) {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, "unable to update ticket")
			return
		}
		writeJSON(w, http.StatusOK, updated)
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodPatch)
	}
}

func (s *server) authorize(w http.ResponseWriter, r *http.Request) (*User, bool) {
	token, err := bearerToken(r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "missing or invalid authorization header")
		return nil, false
	}

	claims, err := parseToken(s.jwtSecret, token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return nil, false
	}

	user, ok := s.store.getUserByID(claims.UserID)
	if !ok || normalizeString(user.Email) != normalizeString(claims.Email) {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return nil, false
	}
	return user, true
}

func (s *store) createUser(name, email, passwordHash string) (*User, error) {
	email = normalizeString(email)
	if email == "" {
		return nil, errors.New("email is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.usersByEmail[email]; exists {
		return nil, errUserExists
	}

	s.nextUserID++
	user := &User{
		ID:           s.nextUserID,
		Name:         strings.TrimSpace(name),
		Email:        email,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now().UTC(),
	}
	s.usersByID[user.ID] = user
	s.usersByEmail[email] = user.ID
	return cloneUser(user), nil
}

func (s *store) getUserByEmail(email string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	userID, ok := s.usersByEmail[normalizeString(email)]
	if !ok {
		return nil, false
	}
	return cloneUser(s.usersByID[userID]), true
}

func (s *store) getUserByID(id int64) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.usersByID[id]
	if !ok {
		return nil, false
	}
	return cloneUser(user), true
}

func (s *store) createTicket(userID int64, title, description string) *Ticket {
	s.mu.Lock()
	defer s.mu.Unlock()

	current := time.Now().UTC()
	s.nextTicketID++
	ticket := &Ticket{
		ID:          s.nextTicketID,
		UserID:      userID,
		Title:       title,
		Description: description,
		Status:      statusOpen,
		CreatedAt:   current,
		UpdatedAt:   current,
	}
	s.ticketsByID[ticket.ID] = ticket
	return cloneTicket(ticket)
}

func (s *store) listTicketsByUser(userID int64) []*Ticket {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tickets := make([]*Ticket, 0)
	for _, ticket := range s.ticketsByID {
		if ticket.UserID == userID {
			tickets = append(tickets, cloneTicket(ticket))
		}
	}
	sort.Slice(tickets, func(i, j int) bool { return tickets[i].ID < tickets[j].ID })
	return tickets
}

func (s *store) getTicket(id int64) (*Ticket, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ticket, ok := s.ticketsByID[id]
	if !ok {
		return nil, false
	}
	return cloneTicket(ticket), true
}

func (s *store) updateTicketStatus(id int64, newStatus string) (*Ticket, error) {
	newStatus = strings.TrimSpace(newStatus)
	if !validStatus(newStatus) {
		return nil, errInvalidStatus
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ticket, ok := s.ticketsByID[id]
	if !ok {
		return nil, errors.New("ticket not found")
	}
	if !isAllowedTransition(ticket.Status, newStatus) {
		return nil, errInvalidTransition
	}
	ticket.Status = newStatus
	ticket.UpdatedAt = time.Now().UTC()
	return cloneTicket(ticket), nil
}

func validStatus(status string) bool {
	switch status {
	case statusOpen, statusInProgress, statusClosed:
		return true
	default:
		return false
	}
}

func isAllowedTransition(current, next string) bool {
	if current == next {
		return true
	}
	switch current {
	case statusOpen:
		return next == statusInProgress
	case statusInProgress:
		return next == statusClosed
	case statusClosed:
		return false
	default:
		return false
	}
}

func cloneUser(user *User) *User {
	if user == nil {
		return nil
	}
	copy := *user
	return &copy
}

func cloneTicket(ticket *Ticket) *Ticket {
	if ticket == nil {
		return nil
	}
	copy := *ticket
	return &copy
}

func readJSONObject(r *http.Request) (map[string]any, error) {
	defer r.Body.Close()
	var payload map[string]any
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(&payload); err != nil {
		return nil, errors.New("invalid JSON payload")
	}
	if payload == nil {
		payload = map[string]any{}
	}
	return payload, nil
}

func firstString(payload map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := payload[key]; ok {
			if text, ok := value.(string); ok {
				return text
			}
		}
	}
	return ""
}

func normalizeString(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func methodNotAllowed(w http.ResponseWriter, allowed ...string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derived := sha256.Sum256(append(salt, []byte(password)...))
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(derived[:]), nil
}

func verifyPassword(password, stored string) bool {
	parts := strings.Split(stored, ":")
	if len(parts) != 2 {
		return false
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	derived := sha256.Sum256(append(salt, []byte(password)...))
	return hmac.Equal(derived[:], expected)
}

func createToken(secret []byte, userID int64, email string, ttl time.Duration) (string, error) {
	now := time.Now().UTC()
	claims := jwtClaims{
		UserID: userID,
		Email:  normalizeString(email),
		Iat:    now.Unix(),
		Exp:    now.Add(ttl).Unix(),
	}

	headerJSON, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payloadJSON, _ := json.Marshal(claims)
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := header + "." + payload
	sig := signHS256(secret, signingInput)
	return signingInput + "." + sig, nil
}

func parseToken(secret []byte, token string) (*jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token")
	}
	toVerify := parts[0] + "." + parts[1]
	if !hmac.Equal([]byte(parts[2]), []byte(signHS256(secret, toVerify))) {
		return nil, errors.New("invalid token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid token")
	}
	var claims jwtClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.New("invalid token")
	}
	if time.Now().UTC().Unix() > claims.Exp {
		return nil, errors.New("token expired")
	}
	return &claims, nil
}

func signHS256(secret []byte, input string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(input))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func bearerToken(header string) (string, error) {
	if header == "" {
		return "", errors.New("missing header")
	}
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || parts[1] == "" {
		return "", errors.New("invalid header")
	}
	return parts[1], nil
}

var (
	errUserExists        = errors.New("user already exists")
	errInvalidStatus     = errors.New("invalid status")
	errInvalidTransition = errors.New("invalid status transition")
)
