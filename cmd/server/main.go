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
	if err := database.InitDB("lite-pam.db"); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	seedData()

	r := gin.Default()
	r.POST("/api/login", handlers.Login)

	api := r.Group("/api")
	api.Use(middleware.AuthMiddleware())
	{
		// 基础
		api.GET("/ping", func(c *gin.Context) {
			c.JSON(200, gin.H{"pong": true})
		})

		// 组与设备
		api.GET("/groups", handlers.ListGroups)
		api.POST("/devices", handlers.CreateDevice)
		api.GET("/devices", handlers.ListDevices)

		// --- Step 7 新增: 密码重置 (回收) ---
		api.POST("/devices/:id/reset", handlers.ResetPassword)

		// 申请流程
		api.POST("/requests", handlers.CreateRequest)
		api.GET("/requests/:id/reveal", handlers.RevealPassword)

		// 管理流程
		api.GET("/admin/pending-requests", handlers.ListPendingRequests)
		api.POST("/requests/:id/approve", handlers.ApproveRequest)

		// --- Step 7 新增: 审计日志 ---
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
