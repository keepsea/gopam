package handlers

import (
	"gopam/internal/database"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ListAuditLogs 查看系统审计日志
func ListAuditLogs(c *gin.Context) {
	// 简单起见，Admin 可以查看所有日志
	// 生产环境通常需要按 Group 过滤，或者只有 SuperAdmin 能看所有
	role := c.GetString("role")
	if role != string(database.RoleAdmin) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin only"})
		return
	}

	var logs []database.AuditLog
	// 只返回最近 50 条
	database.DB.Order("created_at desc").Limit(50).Find(&logs)

	c.JSON(http.StatusOK, logs)
}
