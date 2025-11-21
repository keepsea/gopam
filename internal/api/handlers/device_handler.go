package handlers

import (
	"gopam/internal/database"
	"gopam/internal/security"
	"net/http"
	"os"

	"gorm.io/gorm"

	"github.com/gin-gonic/gin"
)

// getMasterKey 获取系统主密钥，生产环境应从 ENV 读取
func getMasterKey() string {
	key := os.Getenv("APP_MASTER_KEY")
	if key == "" {
		return "default-insecure-master-key-for-demo" // 演示用默认值
	}
	return key
}

type CreateDeviceRequest struct {
	Name            string `json:"name" binding:"required"`
	IP              string `json:"ip" binding:"required"`
	Protocol        string `json:"protocol" binding:"required"`
	GroupID         uint   `json:"group_id" binding:"required"`
	InitialPassword string `json:"initial_password" binding:"required"`
}

// CreateDevice 资产录入 (运维人员自助录入并封存)
func CreateDevice(c *gin.Context) {
	// 1. 解析请求
	var req CreateDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 2. 获取当前操作人 ID
	userID := c.GetUint("userID")

	// 3. 加密初始密码
	// 注意：这里调用了我们在 Step 1 实现的 Encrypt
	encryptedPwd, err := security.Encrypt(getMasterKey(), req.InitialPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
		return
	}

	// 4. 存入数据库
	device := database.Device{
		Name:              req.Name,
		IP:                req.IP,
		Protocol:          req.Protocol,
		GroupID:           req.GroupID,
		CreatedByID:       userID,
		Status:            database.StatusSafe, // 默认状态：在库安全
		EncryptedPassword: encryptedPwd,
	}

	if err := database.DB.Create(&device).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save device"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Device onboarded and secured", "id": device.ID})
}

// ListDevices 设备列表 (实现分权可见性)
func ListDevices(c *gin.Context) {
	role := c.GetString("role")

	var devices []database.Device

	// 预加载关联数据 (Preload Group and Creator info)
	query := database.DB.Preload("Group").Preload("CreatedBy", func(db *gorm.DB) *gorm.DB {
		return db.Select("id", "username") // 仅查询用户名，不查密码hash
	})

	if role == string(database.RoleAdmin) {
		// --- Admin 视角: 仅看管辖组 ---
		// 从 Context 获取中间件注入的 GroupID
		adminGroupID, exists := c.Get("groupID")
		if !exists {
			// 如果是 Admin 但没有分配组，什么都看不到
			c.JSON(http.StatusOK, []database.Device{})
			return
		}
		query = query.Where("group_id = ?", adminGroupID)
	} else {
		// --- User 视角: 查看所有 (或根据具体需求限制) ---
		// 这里暂时允许 Ops 查看所有资产，方便申请
	}

	// 执行查询 (隐藏加密字段，不返回 EncryptedPassword 给列表)
	query.Omit("EncryptedPassword").Find(&devices)

	c.JSON(http.StatusOK, devices)
}
