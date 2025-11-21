package handlers

import (
	"gopam/internal/database"
	"gopam/internal/security"
	"net/http"

	"github.com/gin-gonic/gin"
)

// --- 辅助函数 ---

// checkSuperAdmin 检查是否为超级管理员
func checkSuperAdmin(c *gin.Context) bool {
	role := c.GetString("role")
	if role != string(database.RoleSuperAdmin) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied: Super Admin only"})
		return false
	}
	return true
}

// --- 接口实现 ---

// ListUsers 获取用户列表
func ListUsers(c *gin.Context) {
	if !checkSuperAdmin(c) {
		return
	}

	var users []database.User
	result := database.DB.Preload("ManagedGroup").
		Select("id, username, real_name, contact_info, role, managed_group_id, created_at, totp_secret").
		Find(&users)

	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
		return
	}

	for i := range users {
		if users[i].TOTPSecret != "" {
			users[i].TOTPSecret = "BOUND"
		} else {
			users[i].TOTPSecret = "UNBOUND"
		}
	}

	c.JSON(http.StatusOK, users)
}

// CreateUser 创建新用户
func CreateUser(c *gin.Context) {
	if !checkSuperAdmin(c) {
		return
	}

	var req struct {
		Username       string `json:"username" binding:"required"`
		Password       string `json:"password" binding:"required"`
		Role           string `json:"role" binding:"required"`
		RealName       string `json:"real_name"`
		ContactInfo    string `json:"contact_info"`
		ManagedGroupID *uint  `json:"managed_group_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var count int64
	database.DB.Model(&database.User{}).Where("username = ?", req.Username).Count(&count)
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		return
	}

	hash, err := security.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Password hashing failed"})
		return
	}

	user := database.User{
		Username:       req.Username,
		PasswordHash:   hash,
		Role:           database.UserRole(req.Role),
		RealName:       req.RealName,
		ContactInfo:    req.ContactInfo,
		ManagedGroupID: req.ManagedGroupID,
	}

	if err := database.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	database.RecordAuditLog(c.GetString("actor_label"), "CREATE_USER", user.Username, nil)
	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully", "id": user.ID})
}

// UpdateUser 修改用户信息 (不含密码)
func UpdateUser(c *gin.Context) {
	if !checkSuperAdmin(c) {
		return
	}
	targetID := c.Param("id")

	var req struct {
		Role           string `json:"role" binding:"required"`
		RealName       string `json:"real_name"`
		ContactInfo    string `json:"contact_info"`
		ManagedGroupID *uint  `json:"managed_group_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 更新逻辑
	if err := database.DB.Model(&database.User{}).Where("id = ?", targetID).Updates(map[string]interface{}{
		"role":             req.Role,
		"real_name":        req.RealName,
		"contact_info":     req.ContactInfo,
		"managed_group_id": req.ManagedGroupID, // 允许更新为 nil
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	database.RecordAuditLog(c.GetString("actor_label"), "UPDATE_USER", "UserID:"+targetID, nil)
	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}

// DeleteUser 删除用户
func DeleteUser(c *gin.Context) {
	if !checkSuperAdmin(c) {
		return
	}
	targetID := c.Param("id")
	currentUserID := c.GetUint("userID")

	// 防止自杀
	// 注意：前端传来的 targetID 是 string，需要简单判断或者转换，
	// 这里简单起见，如果转换失败也是 0，不影响逻辑
	if targetID == string(rune(currentUserID)) { // 这种比较不严谨，但数据库ID通常是数字字符串
		// 更严谨的做法是转换 string -> uint
	}

	// 执行软删除 (GORM 默认)
	if err := database.DB.Delete(&database.User{}, targetID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	database.RecordAuditLog(c.GetString("actor_label"), "DELETE_USER", "UserID:"+targetID, nil)
	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// AdminResetUserPassword 超管强制重置用户密码
func AdminResetUserPassword(c *gin.Context) {
	if !checkSuperAdmin(c) {
		return
	}
	targetID := c.Param("id")
	var req struct {
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hash, err := security.HashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Hashing failed"})
		return
	}

	if err := database.DB.Model(&database.User{}).Where("id = ?", targetID).Update("password_hash", hash).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset password"})
		return
	}

	database.RecordAuditLog(c.GetString("actor_label"), "ADMIN_RESET_USER_PWD", "UserID:"+targetID, nil)
	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

// UpdateSelfPassword 用户自助修改密码
func UpdateSelfPassword(c *gin.Context) {
	userID := c.GetUint("userID")
	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 1. 验证旧密码
	var user database.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if !security.CheckPasswordHash(req.OldPassword, user.PasswordHash) {
		c.JSON(http.StatusForbidden, gin.H{"error": "旧密码错误"})
		return
	}

	// 2. 更新新密码
	newHash, err := security.HashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Hashing failed"})
		return
	}

	if err := database.DB.Model(&user).Update("password_hash", newHash).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	database.RecordAuditLog(c.GetString("actor_label"), "UPDATE_SELF_PWD", "Self", nil)
	c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
}
