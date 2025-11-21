package handlers

import (
	"gopam/internal/database"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ListAuditLogs 查看系统审计日志
func ListAuditLogs(c *gin.Context) {
	role := c.GetString("role")

	// [修复] 允许 ADMIN 和 SUPER_ADMIN 查看日志
	if role != string(database.RoleAdmin) && role != string(database.RoleSuperAdmin) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied: Admin only"})
		return
	}

	var logs []database.AuditLog
	// 只返回最近 100 条 (稍微增加一点限制，方便查看)
	database.DB.Order("created_at desc").Limit(100).Find(&logs)

	c.JSON(http.StatusOK, logs)
}
