package handlers

import (
	"gopam/internal/auth"
	"gopam/internal/database"
	"gopam/internal/security"
	"net/http"

	"github.com/gin-gonic/gin"
)

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 1. 查找用户
	var user database.User
	result := database.DB.Where("username = ?", req.Username).First(&user)
	if result.Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// 2. 验证密码
	if !security.CheckPasswordHash(req.Password, user.PasswordHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// 3. 生成 Token
	token, err := auth.GenerateToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// 4. 返回结果
	c.JSON(http.StatusOK, gin.H{
		"token":    token,
		"role":     user.Role,
		"username": user.Username,
		"is_admin": user.Role == database.RoleAdmin,
	})
}
