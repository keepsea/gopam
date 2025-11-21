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
	// 1. 初始化数据库
	// 这一步会连接 SQLite 数据库，如果文件不存在会自动创建
	if err := database.InitDB("lite-pam.db"); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// 2. 数据播种 (增强版: 创建组、Admin、User)
	// 每次启动时检查，如果没数据自动填充，方便开发调试
	seedData()

	// 3. 设置 Gin 路由
	r := gin.Default()

	// 公开路由
	r.POST("/api/login", handlers.Login)

	// 受保护路由 (需要 Header -> Authorization: Bearer <token>)
	api := r.Group("/api")
	api.Use(middleware.AuthMiddleware())
	{
		// --- 基础测试接口 ---
		api.GET("/ping", func(c *gin.Context) {
			uid, _ := c.Get("userID")
			role, _ := c.Get("role")
			gid, _ := c.Get("groupID")
			c.JSON(200, gin.H{"pong": true, "uid": uid, "role": role, "gid": gid})
		})

		// --- 业务接口 (新挂载的) ---

		// 1. 获取设备组列表 (供 User 录入时下拉选择)
		api.GET("/groups", handlers.ListGroups)

		// 2. 录入新设备 (User 操作，含加密逻辑)
		api.POST("/devices", handlers.CreateDevice)

		// 3. 获取设备列表 (实现分权可见性逻辑)
		api.GET("/devices", handlers.ListDevices)
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
// 如果数据库是空的，会自动创建：
// 1. 两个设备组 (Network-Sec, Server-Ops)
// 2. 一个只能管理 Network 组的管理员 (admin_net)
// 3. 一个普通运维用户 (ops_user)
func seedData() {
	var count int64
	database.DB.Model(&database.User{}).Count(&count)
	if count > 0 {
		return // 只要有用户就不重复播种
	}

	log.Println("Seeding initial data...")

	// 1. 创建设备组
	netGroup := database.DeviceGroup{Name: "Network-Sec", Description: "Firewalls & VPNs"}
	svrGroup := database.DeviceGroup{Name: "Server-Ops", Description: "Linux & Windows Servers"}
	database.DB.Create(&netGroup)
	database.DB.Create(&svrGroup)

	// 统一初始密码为 123456
	pwdHash, _ := security.HashPassword("123456")

	// 2. 创建 Admin (绑定权限: 只管 Network 组)
	admin := database.User{
		Username:       "admin_net",
		PasswordHash:   pwdHash,
		Role:           database.RoleAdmin,
		ManagedGroupID: &netGroup.ID, // 关键点：关联了组ID
	}
	database.DB.Create(&admin)

	// 3. 创建 Ops User (运维人员)
	ops := database.User{
		Username:     "ops_user",
		PasswordHash: pwdHash,
		Role:         database.RoleUser,
	}
	database.DB.Create(&ops)

	log.Println("Seeded: [Groups: Network-Sec, Server-Ops], [Users: admin_net, ops_user (pass: 123456)]")
}
