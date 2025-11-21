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

// CORSMiddleware 允许跨域请求
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*") // 生产环境请改为前端域名
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-TOTP-Code")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func main() {
	if err := database.InitDB("lite-pam.db"); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	seedData()

	r := gin.Default()

	// --- 关键修改: 启用 CORS 中间件 ---
	r.Use(CORSMiddleware())

	r.POST("/api/login", handlers.Login)

	api := r.Group("/api")
	api.Use(middleware.AuthMiddleware())
	{
		api.GET("/ping", func(c *gin.Context) {
			c.JSON(200, gin.H{"pong": true})
		})

		// 组与设备
		api.GET("/groups", handlers.ListGroups)
		api.POST("/devices", handlers.CreateDevice)
		api.GET("/devices", handlers.ListDevices)
		api.POST("/devices/:id/reset", handlers.ResetPassword)

		// 申请流程
		api.POST("/requests", handlers.CreateRequest)
		api.GET("/requests/:id/reveal", handlers.RevealPassword)

		// 管理流程
		api.GET("/admin/pending-requests", handlers.ListPendingRequests)
		api.POST("/requests/:id/approve", handlers.ApproveRequest)
		api.GET("/admin/audit-logs", handlers.ListAuditLogs)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server starting on port %s...", port)
	r.Run(":" + port)
}

func seedData() {
	var count int64
	database.DB.Model(&database.User{}).Count(&count)
	if count > 0 {
		return
	}
	log.Println("Seeding initial data...")
	netGroup := database.DeviceGroup{Name: "Network-Sec", Description: "Firewalls & VPNs"}
	svrGroup := database.DeviceGroup{Name: "Server-Ops", Description: "Linux & Windows Servers"}
	database.DB.Create(&netGroup)
	database.DB.Create(&svrGroup)
	pwdHash, _ := security.HashPassword("123456")
	admin := database.User{
		Username:       "admin_net",
		PasswordHash:   pwdHash,
		Role:           database.RoleAdmin,
		ManagedGroupID: &netGroup.ID,
	}
	database.DB.Create(&admin)
	ops := database.User{
		Username:     "ops_user",
		PasswordHash: pwdHash,
		Role:         database.RoleUser,
	}
	database.DB.Create(&ops)
	log.Println("Seeded: [Groups: Network-Sec, Server-Ops], [Users: admin_net, ops_user (pass: 123456)]")
}
