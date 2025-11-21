package handlers

import (
	"gopam/internal/auth"
	"gopam/internal/database"
	"gopam/internal/security"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// CreateRequest 运维人员发起申请
func CreateRequest(c *gin.Context) {
	var req struct {
		DeviceID uint   `json:"device_id" binding:"required"`
		Reason   string `json:"reason" binding:"required"`
		Duration string `json:"duration" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetUint("userID")

	// 创建申请记录
	request := database.Request{
		DeviceID: req.DeviceID,
		UserID:   userID,
		Reason:   req.Reason,
		Duration: req.Duration,
		Status:   database.ReqStatusPending,
	}

	// 同时更新设备状态为 "待审批"
	tx := database.DB.Begin()
	if err := tx.Create(&request).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}
	if err := tx.Model(&database.Device{}).Where("id = ?", req.DeviceID).Update("status", database.StatusPendingApproval).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update device status"})
		return
	}
	tx.Commit()

	c.JSON(http.StatusCreated, gin.H{"message": "Request submitted", "id": request.ID})
}

// ListPendingRequests 管理员查看待审批列表 (分权)
func ListPendingRequests(c *gin.Context) {
	adminGroupID, _ := c.Get("groupID") // 这里用 Get 是因为 groupID 可能为空(非admin)，且 Get 返回 (any, bool)

	var requests []database.Request
	// 关联查询: 只查 Device.GroupID == Admin.ManagedGroupID 的申请
	database.DB.Preload("Device").Preload("User").
		Joins("JOIN devices ON devices.id = requests.device_id").
		Where("requests.status = ? AND devices.group_id = ?", database.ReqStatusPending, adminGroupID).
		Find(&requests)

	c.JSON(http.StatusOK, requests)
}

func ApproveRequest(c *gin.Context) {
	requestID := c.Param("id")

	// 1. 获取 Header 中的 TOTP Code
	totpCode := c.GetHeader("X-TOTP-Code")
	if totpCode == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFA Required: X-TOTP-Code header missing"})
		return
	}

	// --- 真实校验逻辑开始 ---

	// 2. 获取当前 Admin 用户信息 (查数据库获取 Secret)
	adminID := c.GetUint("userID")
	var adminUser database.User
	if err := database.DB.First(&adminUser, adminID).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Admin user not found"})
		return
	}

	// 3. 检查是否已绑定 MFA
	if adminUser.TOTPSecret == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "MFA not setup. Please configure Authenticator in settings first."})
		return
	}

	// 4. 执行 TOTP 校验
	if !auth.ValidateTOTP(totpCode, adminUser.TOTPSecret) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Invalid TOTP code"})
		return
	}

	// --- 真实校验逻辑结束 ---

	// 5. 查找申请单及关联设备
	var req database.Request
	if err := database.DB.Preload("Device").First(&req, requestID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Request not found"})
		return
	}

	// 6. 权限再次校验 (防越权)
	val, exists := c.Get("groupID")
	if !exists {
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
		return
	}
	adminGroupID := val.(uint)

	if req.Device.GroupID != adminGroupID {
		c.JSON(http.StatusForbidden, gin.H{"error": "You do not have permission to approve this device"})
		return
	}

	// 7. 解密密码 (完整性校验)
	_, err := security.Decrypt(getMasterKey(), req.Device.EncryptedPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt password (integrity check failed)"})
		return
	}

	// 8. 事务更新
	now := time.Now()
	tx := database.DB.Begin()

	req.Status = database.ReqStatusApproved
	req.ApproverID = &adminID
	req.ApprovedAt = &now
	tx.Save(&req)

	tx.Model(&req.Device).Update("status", database.StatusApproved)

	tx.Commit()

	c.JSON(http.StatusOK, gin.H{"message": "Approved successfully."})
}

// RevealPassword 运维人员查看密码 (审批通过后)
func RevealPassword(c *gin.Context) {
	requestID := c.Param("id")
	userID := c.GetUint("userID")

	var req database.Request
	if err := database.DB.Preload("Device").First(&req, requestID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Request not found"})
		return
	}

	// 校验: 必须是申请人自己
	if req.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Not your request"})
		return
	}

	// 校验: 必须是已批准状态
	if req.Status != database.ReqStatusApproved {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Request not approved yet"})
		return
	}

	// 解密
	pwd, err := security.Decrypt(getMasterKey(), req.Device.EncryptedPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Decryption error"})
		return
	}

	// 审计日志应在这里记录 (略)

	c.JSON(http.StatusOK, gin.H{
		"device":   req.Device.Name,
		"ip":       req.Device.IP,
		"password": pwd, // 明文返回
	})
}
