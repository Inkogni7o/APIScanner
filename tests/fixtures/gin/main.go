package main
import "github.com/gin-gonic/gin"
func main() {
    app := gin.Default()
    api := app.Group("/api", requireAuth)
    v1 := api.Group("/v1")
    v1.GET("/jobs/:id", show)
    v1.POST("/jobs", func(c *gin.Context) { c.PostForm("command") })
}
func show(c *gin.Context) { c.Query("q"); c.Param("id") }
func requireAuth(c *gin.Context) {}
