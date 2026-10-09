package main

import (
    "database/sql"
    "fmt"
    "net/http"
)

var db *sql.DB

func unsafeSQL(w http.ResponseWriter, r *http.Request) {
    query := fmt.Sprintf("SELECT name FROM users WHERE name = '%s'", r.URL.Query().Get("name"))
    db.Query(query)
}

func safeSQL(w http.ResponseWriter, r *http.Request) {
    db.Query("SELECT name FROM users WHERE name = ?", r.URL.Query().Get("name"))
}

func main() {
    http.HandleFunc("GET /go/sql", unsafeSQL)
    http.HandleFunc("GET /go/safe", safeSQL)
}
