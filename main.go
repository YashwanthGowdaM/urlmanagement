package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

//go:embed index.html
var indexHTML []byte

type Link struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	URL   string `json:"url"`
	Desc  string `json:"desc"`
	Icon  string `json:"icon"`
	Color string `json:"color"`
}

type input struct{ Name, URL, Desc string }

var (
	mu       sync.RWMutex
	links    []Link
	dataFile = env("DATA_FILE", "/data/urls.json")
	adminPw  = os.Getenv("ADMIN_PASSWORD")
	smu      sync.Mutex
	sessions = map[string]time.Time{}
)

const sessionTTL = 24 * time.Hour

// known tool name -> Simple Icons slug
var known = [][2]string{{"github", "github"}, {"gitlab", "gitlab"}, {"jenkins", "jenkins"}, {"grafana", "grafana"},
	{"docker", "docker"}, {"terraform", "terraform"}, {"aws", "amazonaws"}, {"kubernetes", "kubernetes"},
	{"prometheus", "prometheus"}, {"sonarqube", "sonarqube"}, {"portainer", "portainer"}, {"ansible", "ansible"},
	{"nginx", "nginx"}, {"postgres", "postgresql"}, {"jira", "jira"}, {"slack", "slack"}, {"vault", "vault"},
	{"argo", "argo"}, {"harbor", "harbor"}, {"datadog", "datadog"}}

var palette = []string{"#2563eb", "#7c3aed", "#db2777", "#ea580c", "#16a34a", "#0891b2", "#ca8a04", "#4f46e5", "#dc2626", "#0d9488"}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func token(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func decorate(l *Link) {
	n := strings.ToLower(l.Name)
	l.Icon = ""
	for _, k := range known {
		if strings.Contains(n, k[0]) {
			l.Icon = k[1]
			break
		}
	}
	h := 0
	for _, r := range n {
		h = (h*31 + int(r)) & 0xffff
	}
	l.Color = palette[h%len(palette)]
}

func validate(in input) (Link, string) {
	l := Link{Name: strings.TrimSpace(in.Name), URL: strings.TrimSpace(in.URL), Desc: strings.TrimSpace(in.Desc)}
	switch {
	case l.Name == "":
		return l, "Application name is required"
	case utf8.RuneCountInString(l.Name) > 60:
		return l, "Name must be 60 characters or fewer"
	case l.Desc == "":
		return l, "Description is required"
	case utf8.RuneCountInString(l.Desc) > 120:
		return l, "Description must be 120 characters or fewer"
	}
	low := strings.ToLower(l.URL)
	if !strings.HasPrefix(low, "http://") && !strings.HasPrefix(low, "https://") {
		return l, "URL must start with http:// or https://"
	}
	if u, err := url.Parse(l.URL); err != nil || u.Host == "" {
		return l, "URL is not valid"
	}
	decorate(&l)
	return l, ""
}

func load() {
	mu.Lock()
	defer mu.Unlock()
	if b, err := os.ReadFile(dataFile); err == nil {
		if json.Unmarshal(b, &links) == nil {
			return
		}
		log.Printf("could not parse %s, reseeding", dataFile)
	}
	seed := [][3]string{
		{"GitHub", "https://github.com", "Source code, pull requests and issues"},
		{"Jenkins", "https://www.jenkins.io", "CI server for builds and pipelines"},
		{"Grafana", "https://grafana.com", "Dashboards for metrics and logs"},
		{"Docker Hub", "https://hub.docker.com", "Container image registry"},
		{"Terraform Registry", "https://registry.terraform.io", "Providers and modules for infrastructure as code"},
		{"AWS Console", "https://console.aws.amazon.com", "Manage cloud resources and billing"},
		{"Kubernetes Docs", "https://kubernetes.io/docs", "Reference for clusters and workloads"},
		{"Prometheus", "https://prometheus.io", "Metrics collection and alerting"},
		{"SonarQube", "https://www.sonarsource.com/products/sonarqube", "Code quality and security analysis"},
		{"Portainer", "https://www.portainer.io", "Web UI for Docker hosts"},
	}
	links = []Link{}
	for _, s := range seed {
		l := Link{ID: token(4), Name: s[0], URL: s[1], Desc: s[2]}
		decorate(&l)
		links = append(links, l)
	}
	if err := save(); err != nil {
		log.Printf("seed save failed: %v", err)
	}
}

// save must be called with mu held.
func save() error {
	b, _ := json.MarshalIndent(links, "", "  ")
	if err := os.MkdirAll(filepath.Dir(dataFile), 0o755); err != nil {
		return err
	}
	tmp := dataFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, dataFile)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) { writeJSON(w, code, map[string]string{"error": msg}) }

func isAdmin(r *http.Request) bool {
	c, err := r.Cookie("session")
	if err != nil {
		return false
	}
	smu.Lock()
	defer smu.Unlock()
	exp, ok := sessions[c.Value]
	if ok && time.Now().After(exp) {
		delete(sessions, c.Value)
		return false
	}
	return ok
}

func admin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r) {
			fail(w, 401, "Session expired")
			return
		}
		h(w, r)
	}
}

func readBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		fail(w, 400, "Invalid request body")
		return false
	}
	return true
}

func login(w http.ResponseWriter, r *http.Request) {
	if adminPw == "" {
		fail(w, 503, "Admin login is disabled")
		return
	}
	var b struct{ Password string }
	if !readBody(w, r, &b) {
		return
	}
	a, p := sha256.Sum256([]byte(b.Password)), sha256.Sum256([]byte(adminPw))
	if subtle.ConstantTimeCompare(a[:], p[:]) != 1 {
		time.Sleep(600 * time.Millisecond) // slow down guessing
		fail(w, 401, "Incorrect password")
		return
	}
	t := token(32)
	smu.Lock()
	for k, v := range sessions {
		if time.Now().After(v) {
			delete(sessions, k)
		}
	}
	sessions[t] = time.Now().Add(sessionTTL)
	smu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "session", Value: t, Path: "/", MaxAge: int(sessionTTL.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, 200, map[string]bool{"admin": true})
}

func logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("session"); err == nil {
		smu.Lock()
		delete(sessions, c.Value)
		smu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, 200, map[string]bool{"admin": false})
}

func list(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	defer mu.RUnlock()
	writeJSON(w, 200, links)
}

func add(w http.ResponseWriter, r *http.Request) {
	var in input
	if !readBody(w, r, &in) {
		return
	}
	l, msg := validate(in)
	if msg != "" {
		fail(w, 400, msg)
		return
	}
	l.ID = token(4)
	mu.Lock()
	defer mu.Unlock()
	links = append(links, l)
	if err := save(); err != nil {
		links = links[:len(links)-1]
		fail(w, 500, "Could not save")
		return
	}
	writeJSON(w, 201, l)
}

func edit(w http.ResponseWriter, r *http.Request) {
	var in input
	if !readBody(w, r, &in) {
		return
	}
	l, msg := validate(in)
	if msg != "" {
		fail(w, 400, msg)
		return
	}
	id := r.PathValue("id")
	mu.Lock()
	defer mu.Unlock()
	for i := range links {
		if links[i].ID == id {
			l.ID = id
			old := links[i]
			links[i] = l
			if err := save(); err != nil {
				links[i] = old
				fail(w, 500, "Could not save")
				return
			}
			writeJSON(w, 200, l)
			return
		}
	}
	fail(w, 404, "Not found")
}

func del(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	mu.Lock()
	defer mu.Unlock()
	for i := range links {
		if links[i].ID == id {
			old := append([]Link(nil), links...)
			links = append(links[:i], links[i+1:]...)
			if err := save(); err != nil {
				links = old
				fail(w, 500, "Could not save")
				return
			}
			writeJSON(w, 200, map[string]bool{"ok": true})
			return
		}
	}
	fail(w, 404, "Not found")
}

func secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: https://cdn.simpleicons.org; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			hd.Set("Cache-Control", "no-store")
		}
		h.ServeHTTP(w, r)
	})
}

func main() {
	healthFlag := flag.Bool("health", false, "check the running server and exit")
	flag.Parse()
	addr := env("ADDR", ":8080")
	if *healthFlag {
		c := http.Client{Timeout: 3 * time.Second}
		resp, err := c.Get("http://127.0.0.1" + addr[strings.LastIndex(addr, ":"):] + "/api/urls")
		if err != nil || resp.StatusCode != 200 {
			os.Exit(1)
		}
		return
	}
	load()
	if adminPw == "" {
		log.Println("ADMIN_PASSWORD is empty: admin login is disabled")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/urls", list)
	mux.HandleFunc("GET /api/me", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]bool{"admin": isAdmin(r)}) })
	mux.HandleFunc("POST /api/login", login)
	mux.HandleFunc("POST /api/logout", logout)
	mux.HandleFunc("POST /api/urls", admin(add))
	mux.HandleFunc("PUT /api/urls/{id}", admin(edit))
	mux.HandleFunc("DELETE /api/urls/{id}", admin(del))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})
	srv := &http.Server{Addr: addr, Handler: secure(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second}
	fmt.Println("MyURLs listening on", addr)
	log.Fatal(srv.ListenAndServe())
}
