package routes

import (
	controller "github.com/mrofia/deall-api-go/controllers"
	middleware "github.com/mrofia/deall-api-go/middleware"

	"github.com/gin-gonic/gin"
)

// UserRoutes function
func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("/users/signup", controller.SignUp())
	incomingRoutes.POST("/users/login", controller.Login())

	auth := middleware.Authentication()
	incomingRoutes.GET("/users/list", auth, controller.GetUsers())
}
