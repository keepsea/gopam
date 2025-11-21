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

		// 注入基础信息
		c.Set("userID", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)
		if claims.ManagedGroupID != nil {
			c.Set("groupID", *claims.ManagedGroupID)
		}

		// [新增] 构建审计专用的显示名称 (格式: 真实姓名 (账号))
		// 如果没有真实姓名，则只显示账号
		actorLabel := claims.Username
		if claims.RealName != "" {
			actorLabel = claims.RealName + " (" + claims.Username + ")"
		}
		c.Set("actor_label", actorLabel)

		c.Next()
	}
}
