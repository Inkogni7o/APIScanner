package main
import "github.com/gin-gonic/gin"
import "os/exec"
func main() {
    app := gin.New()
    app.GET("/go/run", func(c *gin.Context) { execute(c.Query("command")) })
}
func execute(command string) { exec.Command("sh", "-c", command).Run() }
