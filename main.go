package main

import (
	"os"

	middleware "github.com/mrofia/deall-api-go/middleware"
	routes "github.com/mrofia/deall-api-go/routes"

	"github.com/gin-gonic/gin"
)

func main() {
	port := os.Getenv("PORT")

	if port == "" {
		port = "8000"
	}

	router := gin.New()
	router.Use(gin.Logger())
	routes.UserRoutes(router)

	//router.Use(middleware.Authentication())

	auth := middleware.Authentication()
	// API-2
	router.GET("/api-1", auth, func(c *gin.Context) {

		c.JSON(200, gin.H{"success": "Access granted for api-1"})

	})

	// API-1
	router.GET("/api-2", auth, func(c *gin.Context) {
		c.JSON(200, gin.H{"success": "Access granted for api-2"})
	})

	router.Run(":" + port)
}
