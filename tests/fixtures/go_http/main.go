package main

import (
    "net/http"
    "os"
)

func main() {
    mux := http.NewServeMux()
    register(mux)
    http.HandleFunc("POST /proxy", func(w http.ResponseWriter, r *http.Request) {
        http.Get(r.FormValue("url"))
    })
}

func register(mux *http.ServeMux) {
    mux.HandleFunc("GET /files/{name}", read)
}

func read(w http.ResponseWriter, r *http.Request) {
    data, _ := os.ReadFile(r.PathValue("name"))
    w.Write(data)
}
