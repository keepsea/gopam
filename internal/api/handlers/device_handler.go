package handlers

import (
	"gopam/internal/database"
	"gopam/internal/security"
	"gopam/internal/state"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Helper: 从内存金库获取 Data Encryption Key (DEK)
// 如果金库被锁定（管理员未输入口令或超时），则拒绝服务
func getDEK(c *gin.Context) []byte {
	dek := state.GlobalVault.GetDEK()
	if dek == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Vault is locked. Please unlock first."})
		return nil
	}
	return dek
}

type CreateDeviceRequest struct {
	Name            string `json:"name" binding:"required"`
	IP              string `json:"ip" binding:"required"`
	Protocol        string `json:"protocol" binding:"required"`
	GroupID         uint   `json:"group_id" binding:"required"`
	InitialPassword string `json:"initial_password" binding:"required"`
}

// CreateDevice 资产录入
// 运维人员录入新设备，需要系统处于“解锁”状态以获取加密密钥
func CreateDevice(c *gin.Context) {
	// 1. 获取加密密钥
	dek := getDEK(c)
	if dek == nil {
		return
	} // 拦截

	var req CreateDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetUint("userID")

	// 2. 使用 DEK 直接加密初始密码
	encryptedPwd, err := security.EncryptRaw(dek, req.InitialPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
		return
	}

	// 3. 存入数据库
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

	// 4. 记录审计日志
	database.RecordAuditLog(c.GetString("actor_label"), "CREATE_DEVICE", device.Name, gin.H{"ip": device.IP})
	c.JSON(http.StatusCreated, gin.H{"message": "Device onboarded and secured", "id": device.ID})
}

// ListDevices 设备列表
// 根据角色（Admin/User）和管辖组进行过滤
func ListDevices(c *gin.Context) {
	role := c.GetString("role")
	var devices []database.Device

	// 预加载关联数据
	query := database.DB.Preload("Group").Preload("CreatedBy", func(db *gorm.DB) *gorm.DB {
		return db.Select("id", "username")
	})

	// 权限过滤：组管理员只能看自己组的设备
	if role == string(database.RoleAdmin) {
		adminGroupID, exists := c.Get("groupID")
		if !exists {
			c.JSON(http.StatusOK, []database.Device{})
			return
		}
		query = query.Where("group_id = ?", adminGroupID)
	}

	// 永远不返回加密后的密码字段
	query.Omit("EncryptedPassword").Find(&devices)
	c.JSON(http.StatusOK, devices)
}

// ResetPassword 管理员重置密码 (回收流程)
// 包含事务处理：更新密码 + 关闭所有活跃申请
func ResetPassword(c *gin.Context) {
	// 1. 获取加密密钥
	dek := getDEK(c)
	if dek == nil {
		return
	}

	deviceID := c.Param("id")
	var req struct {
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 2. 查找设备
	var device database.Device
	if err := database.DB.First(&device, deviceID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
		return
	}

	// 3. 权限检查
	val, exists := c.Get("groupID")
	if !exists {
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied: admin group not found"})
		return
	}
	adminGroupID := val.(uint)

	if device.GroupID != adminGroupID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied: not your group"})
		return
	}

	// 4. 加密新密码
	encryptedPwd, err := security.EncryptRaw(dek, req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
		return
	}

	// 5. 开启事务 (关键安全步骤)
	tx := database.DB.Begin()

	// 5.1 更新设备表：写入新密文，状态重置为 SAFE
	if err := tx.Model(&device).Updates(map[string]interface{}{
		"encrypted_password": encryptedPwd,
		"status":             database.StatusSafe,
	}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database update failed"})
		return
	}

	// 5.2 关闭活跃申请：找到所有针对该设备且状态为 APPROVED 的申请，强制改为 COMPLETED
	// 这防止了运维人员通过旧的申请单查看新修改的密码
	if err := tx.Model(&database.Request{}).
		Where("device_id = ? AND status = ?", device.ID, database.ReqStatusApproved).
		Update("status", database.ReqStatusCompleted).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to close active requests"})
		return
	}

	tx.Commit()

	// 6. 记录审计日志
	database.RecordAuditLog(
		c.GetString("actor_label"),
		"RESET_PASSWORD",
		device.Name,
		gin.H{"status_before": "IN_USE/PENDING", "status_after": "SAFE", "action": "Session Terminated"},
	)

	c.JSON(http.StatusOK, gin.H{"message": "Password rotated and all active sessions terminated"})
}
