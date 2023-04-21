package routes

import (
	controller "github.com/mrofia/deall-api-go/controllers"
	middleware "github.com/mrofia/deall-api-go/middleware"

	"github.com/gin-gonic/gin"
)

// UserRoutes function
func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("/users/login", controller.Login())

	auth := middleware.Authentication()

	incomingRoutes.GET("/users/profile", auth, controller.GetProfile())
	incomingRoutes.GET("/users/list", auth, middleware.Authorize("admin"), controller.GetUsers())
	incomingRoutes.PUT("/users/:id", auth, middleware.Authorize("admin"), controller.UpdateUser())
	incomingRoutes.POST("/users/add", auth, middleware.Authorize("admin"), controller.Add())

}
