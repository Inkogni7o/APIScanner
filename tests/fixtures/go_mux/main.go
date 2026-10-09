package main

import (
    "github.com/gorilla/mux"
    "net/http"
    "os/exec"
)

func main() {
    r := mux.NewRouter()
    api := r.PathPrefix("/api").Subrouter()
    api.HandleFunc("/run", run).Methods("POST", "PUT")
}

func run(w http.ResponseWriter, r *http.Request) {
    exec.Command("sh", "-c", r.FormValue("command")).Run()
}
