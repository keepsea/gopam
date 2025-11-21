package handlers

import (
	"gopam/internal/database"
	"gopam/internal/security"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// getMasterKey 获取系统主密钥
func getMasterKey() string {
	key := os.Getenv("APP_MASTER_KEY")
	if key == "" {
		return "default-insecure-master-key-for-demo"
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

// CreateDevice 资产录入
func CreateDevice(c *gin.Context) {
	var req CreateDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetUint("userID")
	encryptedPwd, err := security.Encrypt(getMasterKey(), req.InitialPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
		return
	}

	device := database.Device{
		Name:              req.Name,
		IP:                req.IP,
		Protocol:          req.Protocol,
		GroupID:           req.GroupID,
		CreatedByID:       userID,
		Status:            database.StatusSafe,
		EncryptedPassword: encryptedPwd,
	}

	if err := database.DB.Create(&device).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save device"})
		return
	}

	// 记录审计日志
	database.RecordAuditLog(c.GetString("username"), "CREATE_DEVICE", device.Name, gin.H{"ip": device.IP})

	c.JSON(http.StatusCreated, gin.H{"message": "Device onboarded and secured", "id": device.ID})
}

// ListDevices 设备列表
func ListDevices(c *gin.Context) {
	role := c.GetString("role")
	var devices []database.Device

	query := database.DB.Preload("Group").Preload("CreatedBy", func(db *gorm.DB) *gorm.DB {
		return db.Select("id", "username")
	})

	if role == string(database.RoleAdmin) {
		adminGroupID, exists := c.Get("groupID")
		if !exists {
			c.JSON(http.StatusOK, []database.Device{})
			return
		}
		query = query.Where("group_id = ?", adminGroupID)
	}

	query.Omit("EncryptedPassword").Find(&devices)
	c.JSON(http.StatusOK, devices)
}

// ResetPassword 管理员重置密码 (回收流程)
func ResetPassword(c *gin.Context) {
	deviceID := c.Param("id")
	var req struct {
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 1. 查找设备
	var device database.Device
	if err := database.DB.First(&device, deviceID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
		return
	}

	// 2. 权限检查: 只有该组 Admin 能重置
	// 修正: 使用 c.Get 获取 interface{} 并进行类型断言
	val, exists := c.Get("groupID")
	if !exists {
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied: admin group not found"})
		return
	}
	adminGroupID := val.(uint) // 安全断言，因为中间件里存的就是 uint

	if device.GroupID != adminGroupID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied: not your group"})
		return
	}

	// 3. 加密新密码
	encryptedPwd, err := security.Encrypt(getMasterKey(), req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
		return
	}

	// 4. 更新数据库: 密码变更为新密码，状态回归 SAFE
	if err := database.DB.Model(&device).Updates(map[string]interface{}{
		"encrypted_password": encryptedPwd,
		"status":             database.StatusSafe,
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database update failed"})
		return
	}

	// 5. 记录审计日志
	actorID := c.GetUint("userID")
	database.RecordAuditLog(
		"UserID:"+string(rune(actorID)),
		"RESET_PASSWORD",
		device.Name,
		gin.H{"status_before": "IN_USE/PENDING", "status_after": "SAFE"},
	)

	c.JSON(http.StatusOK, gin.H{"message": "Password rotated and device recycled to SAFE status"})
}
