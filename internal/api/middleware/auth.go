package middleware

import (
	"gopam/internal/auth"
	"strings"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware 验证 Request Header 中的 Bearer Token
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "Authorization header required"})
			return
		}

		// 格式: "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(401, gin.H{"error": "Invalid authorization header format"})
			return
		}

		claims, err := auth.ParseToken(parts[1])
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "Invalid or expired token"})
			return
		}

		// 将用户信息存入 Context，供后续 Handler 使用
		c.Set("userID", claims.UserID)
		c.Set("role", claims.Role)
		if claims.ManagedGroupID != nil {
			c.Set("groupID", *claims.ManagedGroupID)
		}

		c.Next()
	}
}
