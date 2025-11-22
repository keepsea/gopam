package handlers

import (
	"encoding/base64"
	"gopam/internal/database"
	"gopam/internal/security"
	"gopam/internal/state"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// CheckVaultStatus 检查金库状态
func CheckVaultStatus(c *gin.Context) {
	var config database.SystemConfig
	initialized := false
	// [修复] 使用 config_key 查询，避免 SQL 关键字冲突
	if err := database.DB.First(&config, "config_key = ?", "MASTER_DEK").Error; err == nil {
		initialized = true
	}

	unlocked := state.GlobalVault.IsUnlocked()

	c.JSON(http.StatusOK, gin.H{
		"initialized": initialized,
		"unlocked":    unlocked,
	})
}

// SetupVault 初始化金库 (仅首次，需超级管理员)
func SetupVault(c *gin.Context) {
	role := c.GetString("role")
	if role != string(database.RoleSuperAdmin) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
		return
	}

	var req struct {
		VaultPassword string `json:"vault_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var count int64
	// [修复] 使用 config_key 查询
	database.DB.Model(&database.SystemConfig{}).Where("config_key = ?", "MASTER_DEK").Count(&count)
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Vault already initialized"})
		return
	}

	// 1. 生成随机 DEK
	dek, err := security.GenerateRandomKey()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate DEK"})
		return
	}

	// 2. 生成随机 Salt
	salt, err := security.GenerateRandomSalt()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate Salt"})
		return
	}

	// 3. 基于口令派生 KEK
	kek := security.DeriveKeyFromPassword(req.VaultPassword, salt)

	// 4. 加密 DEK
	encryptedDEK, err := security.WrapKey(kek, dek)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to wrap key"})
		return
	}

	// 5. 存入数据库
	config := database.SystemConfig{
		ConfigKey:    "MASTER_DEK", // [修复] 字段名变更
		EncryptedDEK: encryptedDEK,
		Salt:         base64.StdEncoding.EncodeToString(salt),
	}

	// [修复] 增加错误检查，防止静默失败
	if err := database.DB.Create(&config).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database write failed: " + err.Error()})
		return
	}

	// 初始化后默认解锁 30 分钟
	state.GlobalVault.Unlock(dek, 30*time.Minute)

	database.RecordAuditLog(c.GetString("actor_label"), "SETUP_VAULT", "System", nil, nil)
	c.JSON(http.StatusOK, gin.H{"message": "Vault initialized and unlocked"})
}

// UnlockVault 解锁金库
func UnlockVault(c *gin.Context) {
	// [权限收敛] 仅超级管理员可以执行解锁操作
	role := c.GetString("role")
	if role != string(database.RoleSuperAdmin) {
		c.JSON(http.StatusForbidden, gin.H{"error": "权限不足：仅超级管理员持有金库口令"})
		return
	}

	var req struct {
		VaultPassword string `json:"vault_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 1. 读取数据库配置
	var config database.SystemConfig
	// [修复] 使用 config_key 查询
	if err := database.DB.First(&config, "config_key = ?", "MASTER_DEK").Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Vault not initialized"})
		return
	}

	// 2. 解码 Salt
	salt, _ := base64.StdEncoding.DecodeString(config.Salt)

	// 3. 派生 KEK
	kek := security.DeriveKeyFromPassword(req.VaultPassword, salt)

	// 4. 尝试解密 DEK
	dek, err := security.UnwrapKey(kek, config.EncryptedDEK)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "Invalid vault password"})
		return
	}

	// 5. 存入内存 (优化：有效期延长至 12 小时，方便一天的工作)
	state.GlobalVault.Unlock(dek, 12*time.Hour)

	database.RecordAuditLog(c.GetString("actor_label"), "UNLOCK_VAULT", "System", nil, nil)
	c.JSON(http.StatusOK, gin.H{"message": "Vault unlocked for 12 hours"})
}

// LockVault 手动锁定
func LockVault(c *gin.Context) {
	// [权限收敛] 仅超级管理员可以锁定
	role := c.GetString("role")
	if role != string(database.RoleSuperAdmin) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
		return
	}

	state.GlobalVault.Lock()
	database.RecordAuditLog(c.GetString("actor_label"), "LOCK_VAULT", "System", nil, nil)
	c.JSON(http.StatusOK, gin.H{"message": "Vault locked"})
}
