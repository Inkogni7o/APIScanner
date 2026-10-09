package api

import (
    "github.com/go-chi/chi/v5"
)

func Register(r chi.Router) {
    r.Get("/run", Run)
    r.Get("/files/{name}", Read)
    r.Get("/proxy", Proxy)
    r.Get("/safe", Safe)
}
