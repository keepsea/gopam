package handlers

import (
	"gopam/internal/auth"
	"gopam/internal/database"
	"gopam/internal/security"
	"gopam/internal/state"
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

	// [新增] 需要查询 Device 对应的 GroupID 用于记录日志
	var device database.Device
	if err := database.DB.First(&device, req.DeviceID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
		return
	}

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

	// 审计日志
	// [修改] 传入 GroupID
	database.RecordAuditLog(
		c.GetString("actor_label"),
		"CREATE_REQUEST",
		"Request #"+string(rune(request.ID)),
		gin.H{"device_id": req.DeviceID, "reason": req.Reason},
		&device.GroupID,
	)

	c.JSON(http.StatusCreated, gin.H{"message": "Request submitted", "id": request.ID})
}

// ListPendingRequests 管理员查看待审批列表 (分权)
func ListPendingRequests(c *gin.Context) {
	adminGroupID, _ := c.Get("groupID")

	var requests []database.Request
	// 关联查询: 只查 Device.GroupID == Admin.ManagedGroupID 的申请
	database.DB.Preload("Device").Preload("User").
		Joins("JOIN devices ON devices.id = requests.device_id").
		Where("requests.status = ? AND devices.group_id = ?", database.ReqStatusPending, adminGroupID).
		Find(&requests)

	c.JSON(http.StatusOK, requests)
}

// ApproveRequest 管理员审批 (真实 TOTP + 金库解密校验)
func ApproveRequest(c *gin.Context) {
	// 1. 检查金库状态 (审批需要解密验证数据完整性，虽然不返回密码，但需确保DEK可用)
	dek := state.GlobalVault.GetDEK()
	if dek == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Vault is locked. Please unlock first."})
		return
	}

	requestID := c.Param("id")

	// 2. 获取 Header 中的 TOTP Code
	totpCode := c.GetHeader("X-TOTP-Code")
	if totpCode == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFA Required: X-TOTP-Code header missing"})
		return
	}

	adminID := c.GetUint("userID")
	var adminUser database.User
	if err := database.DB.First(&adminUser, adminID).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Admin user not found"})
		return
	}

	// 3. 检查是否已绑定 MFA
	if adminUser.TOTPSecret == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "MFA not setup."})
		return
	}

	// 4. 执行 TOTP 校验
	if !auth.ValidateTOTP(totpCode, adminUser.TOTPSecret) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Invalid TOTP code"})
		return
	}

	var req database.Request
	if err := database.DB.Preload("Device").Preload("User").First(&req, requestID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Request not found"})
		return
	}

	// 5. 权限再次校验 (防越权)
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

	// 6. 使用 DEK 尝试解密 (完整性校验，确保密码数据未损坏)
	_, err := security.DecryptRaw(dek, req.Device.EncryptedPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt password (integrity check failed)"})
		return
	}

	// 7. 事务更新
	now := time.Now()
	tx := database.DB.Begin()

	req.Status = database.ReqStatusApproved
	req.ApproverID = &adminID
	req.ApprovedAt = &now
	tx.Save(&req)

	tx.Model(&req.Device).Update("status", database.StatusApproved)

	tx.Commit()

	// 8. 审计日志
	// [修改] 传入 GroupID
	database.RecordAuditLog(
		c.GetString("actor_label"),
		"APPROVE_REQUEST",
		req.Device.Name,
		gin.H{"applicant": req.User.Username, "reason": req.Reason},
		&req.Device.GroupID,
	)

	c.JSON(http.StatusOK, gin.H{"message": "Approved successfully."})
}

// RevealPassword 运维人员查看密码 (审批通过后)
func RevealPassword(c *gin.Context) {
	// 1. 检查金库状态 (必须有 DEK 才能解密)
	dek := state.GlobalVault.GetDEK()
	if dek == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Vault is locked. Ask Admin to unlock."})
		return
	}

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

	// 解密: 使用 DEK 解密
	pwd, err := security.DecryptRaw(dek, req.Device.EncryptedPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Decryption error"})
		return
	}

	// 审计日志 (核心安全记录)
	// [修改] 传入 GroupID
	database.RecordAuditLog(
		c.GetString("actor_label"),
		"VIEW_PASSWORD",
		req.Device.Name,
		gin.H{"ip": c.ClientIP()},
		&req.Device.GroupID,
	)

	c.JSON(http.StatusOK, gin.H{
		"device":   req.Device.Name,
		"ip":       req.Device.IP,
		"password": pwd, // 明文返回
	})
}

// ListMyRequests 获取当前登录用户的申请记录 (用于前端“集成查看”功能)
func ListMyRequests(c *gin.Context) {
	userID := c.GetUint("userID")

	var requests []database.Request
	// 查询属于当前用户的申请，按时间倒序
	// 预加载 Device 信息以便前端展示
	result := database.DB.Preload("Device").
		Where("user_id = ?", userID).
		Order("created_at desc").
		Find(&requests)

	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch requests"})
		return
	}

	c.JSON(http.StatusOK, requests)
}
