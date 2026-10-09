package main

import (
    "github.com/go-chi/chi/v5"
    "example.com/service/internal/api"
)

func main() {
    router := chi.NewRouter()
    router.Route("/api", func(r chi.Router) { api.Register(r) })
}
