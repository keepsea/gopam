package handlers

import (
	"gopam/internal/auth"
	"gopam/internal/database"
	"net/http"

	"github.com/gin-gonic/gin"
)

// SetupTOTP 第一步：生成密钥和二维码
// 返回: secret (临时展示), qr_image (Base64)
func SetupTOTP(c *gin.Context) {
	userID := c.GetUint("userID")
	var user database.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// 生成密钥
	// 注意：此时还没存入数据库，需要用户扫描并验证一次后才存
	secret, qrBytes, _, err := auth.GenerateTOTPSecret(user.Username, "LitePAM")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate TOTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"secret":   secret,
		"qr_image": qrBytes, // Gin 会自动将 []byte 转为 Base64 字符串
	})
}

// ActivateTOTP 第二步：验证并绑定
// 用户扫描后输入 6 位码，验证成功则将 Secret 写入数据库
func ActivateTOTP(c *gin.Context) {
	var req struct {
		Secret string `json:"secret" binding:"required"`
		Code   string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetUint("userID")

	// 1. 验证动态码是否与上传的 Secret 匹配
	if !auth.ValidateTOTP(req.Code, req.Secret) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Invalid TOTP code"})
		return
	}

	// 2. 验证通过，将 Secret 持久化到 User 表
	if err := database.DB.Model(&database.User{}).Where("id = ?", userID).Update("totp_secret", req.Secret).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save secret"})
		return
	}

	// 3. 记录审计
	database.RecordAuditLog(c.GetString("username"), "ACTIVATE_MFA", "Self", nil)

	c.JSON(http.StatusOK, gin.H{"message": "MFA activated successfully"})
}
