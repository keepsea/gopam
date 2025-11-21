package main

import (
	"gopam/internal/api/handlers"
	"gopam/internal/api/middleware"
	"gopam/internal/database"
	"gopam/internal/security"
	"log"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	// 1. 初始化数据库 (使用本地文件 lite-pam.db)
	if err := database.InitDB("lite-pam.db"); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// 2. 数据播种 (Seeding) - 仅用于演示，创建一个默认管理员
	seedDefaultUser()

	// 3. 设置 Gin 路由
	r := gin.Default()

	// 公开路由
	r.POST("/api/login", handlers.Login)

	// 受保护路由 (需要 Header: Authorization: Bearer <token>)
	api := r.Group("/api")
	api.Use(middleware.AuthMiddleware())
	{
		api.GET("/ping", func(c *gin.Context) {
			// 获取中间件注入的用户信息
			uid, _ := c.Get("userID")
			role, _ := c.Get("role")
			c.JSON(200, gin.H{"message": "pong", "user_id": uid, "role": role})
		})
	}

	// 4. 启动服务
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server starting on port %s...", port)
	r.Run(":" + port)
}

// seedDefaultUser 创建一个默认用户方便测试
// 账号: admin / 密码: password123
func seedDefaultUser() {
	var count int64
	database.DB.Model(&database.User{}).Count(&count)
	if count == 0 {
		hash, _ := security.HashPassword("password123")
		admin := database.User{
			Username:     "admin",
			PasswordHash: hash,
			Role:         database.RoleAdmin,
		}
		database.DB.Create(&admin)
		log.Println("Seeded default user: admin / password123")
	}
}
