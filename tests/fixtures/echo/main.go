package main
import "github.com/labstack/echo/v4"
func main() {
    app := echo.New()
    api := app.Group("/api", requireAuth)
    api.GET("/jobs/:id", show)
    api.POST("/jobs", func(c echo.Context) error { c.FormValue("command"); return nil })
}
func show(c echo.Context) error { c.QueryParam("q"); return nil }
func requireAuth(next echo.HandlerFunc) echo.HandlerFunc { return next }
