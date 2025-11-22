package handlers

import (
	"gopam/internal/auth"
	"gopam/internal/database"
	"net/http"

	"github.com/gin-gonic/gin"
)

func SetupTOTP(c *gin.Context) {
	userID := c.GetUint("userID")
	var user database.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	secret, qrBytes, _, err := auth.GenerateTOTPSecret(user.Username, "LitePAM")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate TOTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"secret":   secret,
		"qr_image": qrBytes,
	})
}

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

	if !auth.ValidateTOTP(req.Code, req.Secret) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Invalid TOTP code"})
		return
	}

	if err := database.DB.Model(&database.User{}).Where("id = ?", userID).Update("totp_secret", req.Secret).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save secret"})
		return
	}

	// [修改] 使用 actor_label 记录姓名
	database.RecordAuditLog(c.GetString("actor_label"), "ACTIVATE_MFA", "Self", nil, nil)

	c.JSON(http.StatusOK, gin.H{"message": "MFA activated successfully"})
}
