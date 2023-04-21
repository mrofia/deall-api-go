package middleware

import (
	"net/http"

	helper "github.com/mrofia/deall-api-go/helpers"

	"github.com/gin-gonic/gin"
)

func Authentication() gin.HandlerFunc {
	return func(c *gin.Context) {

		clientToken := c.Request.Header.Get("token")
		if clientToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing authentication token"})
			c.Abort()
			return
		}

		claims, err := helper.ValidateToken(clientToken)
		if err != "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err})
			c.Abort()
			return
		}

		c.Set("email", claims.Email)
		c.Set("first_name", claims.First_name)
		c.Set("last_name", claims.Last_name)
		c.Set("role", claims.Role)
		c.Set("uid", claims.Uid)

		c.Next()
	}
}

func Authorize(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("uid")
		role := c.GetString("role")

		if contains(allowedRoles, role) {
			c.Next()
		} else if role == "admin" {
			// Allow admins to access any functionality
			c.Next()
		} else if role == "user" {
			// Allow users to only access their own data
			requestedUserID := c.Param("id")

			if requestedUserID == userID {
				c.Next()
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				c.Abort()
			}
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
		}
	}
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
