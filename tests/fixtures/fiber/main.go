package main
import "github.com/gofiber/fiber/v2"
func main() {
    app := fiber.New()
    api := app.Group("/api", requireAuth)
    api.Get("/jobs/:id", show)
    api.Post("/jobs", func(c *fiber.Ctx) error { c.FormValue("command"); return nil })
}
func show(c *fiber.Ctx) error { c.Query("q"); return nil }
func requireAuth(c *fiber.Ctx) error { return c.Next() }
