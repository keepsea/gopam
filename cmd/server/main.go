package main

import (
	"gopam/internal/api/handlers"
	"gopam/internal/api/middleware"
	"gopam/internal/database"

	//"gopam/internal/security"
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

		// [关键修复] 确保包含 DELETE, PUT 等方法
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func main() {
	// --- [新增] 智能判断数据库路径 ---
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		// 如果环境变量未设置，检查是否在 Docker 环境 (/app/data 目录是否存在)
		if _, err := os.Stat("/app/data"); !os.IsNotExist(err) {
			// Docker 环境: 数据存放在挂载卷中
			dbPath = "/app/data/lite-pam.db"
			log.Println("Running in Docker mode, using database: /app/data/lite-pam.db")
		} else {
			// 本地开发环境: 数据存放在当前目录
			dbPath = "lite-pam.db"
			log.Println("Running in Local mode, using database: lite-pam.db")
		}
	} else {
		log.Printf("Using custom database path from ENV: %s", dbPath)
	}

	// 1. 初始化数据库
	if err := database.InitDB(dbPath); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// 2. 数据播种 (初始化超级管理员等)
	//seedData()

	// 3. 设置 Gin 路由
	r := gin.Default()

	// 启用 CORS 中间件
	r.Use(CORSMiddleware())

	// 公开路由
	r.POST("/api/login", handlers.Login)

	// 受保护路由 (需要 Authorization: Bearer <token>)
	api := r.Group("/api")
	api.Use(middleware.AuthMiddleware())
	{
		// --- 基础测试 ---
		api.GET("/ping", func(c *gin.Context) {
			c.JSON(200, gin.H{"pong": true})
		})

		// --- 金库管理 (Vault) ---
		api.GET("/vault/status", handlers.CheckVaultStatus)
		api.POST("/vault/setup", handlers.SetupVault)
		api.POST("/vault/unlock", handlers.UnlockVault)
		api.POST("/vault/lock", handlers.LockVault)

		// --- 组管理 (超级管理员) ---
		api.GET("/groups", handlers.ListGroups)
		api.POST("/admin/groups", handlers.CreateGroup)
		api.PUT("/admin/groups/:id", handlers.UpdateGroup)
		api.DELETE("/admin/groups/:id", handlers.DeleteGroup)

		// --- 设备管理 ---
		api.POST("/devices", handlers.CreateDevice)
		api.GET("/devices", handlers.ListDevices)
		api.POST("/devices/:id/reset", handlers.ResetPassword)

		// --- 申请与借用流程 ---
		api.POST("/requests", handlers.CreateRequest)
		api.GET("/requests/my", handlers.ListMyRequests) // 我的申请列表
		api.GET("/requests/:id/reveal", handlers.RevealPassword)

		// --- 审批与审计流程 ---
		api.GET("/admin/pending-requests", handlers.ListPendingRequests)
		api.POST("/requests/:id/approve", handlers.ApproveRequest)
		api.GET("/admin/audit-logs", handlers.ListAuditLogs)

		// --- MFA (TOTP) 设置 ---
		api.POST("/auth/totp/setup", handlers.SetupTOTP)       // 获取密钥和二维码
		api.POST("/auth/totp/activate", handlers.ActivateTOTP) // 验证验证码并绑定

		// --- 用户管理 (超级管理员) ---
		api.GET("/admin/users", handlers.ListUsers)
		api.POST("/admin/users", handlers.CreateUser)
		api.PUT("/admin/users/:id", handlers.UpdateUser)
		api.DELETE("/admin/users/:id", handlers.DeleteUser)
		api.PUT("/admin/users/:id/password", handlers.AdminResetUserPassword)

		// --- 个人设置 ---
		api.PUT("/user/password", handlers.UpdateSelfPassword)
	}

	// 4. 启动服务
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server starting on port %s...", port)
	r.Run(":" + port)
}

// seedData 初始化演示数据
/*
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

	// 1. 超级管理员 (system_root)
	superAdmin := database.User{
		Username:     "system_root",
		PasswordHash: pwdHash,
		Role:         database.RoleSuperAdmin,
		RealName:     "System Administrator",
		ContactInfo:  "root@localhost",
	}
	database.DB.Create(&superAdmin)
*/
