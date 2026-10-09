package api

import (
    "github.com/go-chi/chi/v5"
    "net/http"
    "os"
    "os/exec"
)

func Run(w http.ResponseWriter, r *http.Request) {
    command := r.URL.Query().Get("command")
    output, _ := exec.Command("sh", "-c", command).Output()
    w.Write(output)
}

func Read(w http.ResponseWriter, r *http.Request) {
    name := chi.URLParam(r, "name")
    data, _ := os.ReadFile("/srv/files/" + name)
    w.Write(data)
}

func Proxy(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    http.Get(url)
}

func Safe(w http.ResponseWriter, r *http.Request) {
    argument := r.URL.Query().Get("argument")
    exec.Command("echo", argument).Run()
    http.Get("https://example.com/health")
}
