package handlers

import (
	"gopam/internal/database"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ListAuditLogs 查看系统审计日志
func ListAuditLogs(c *gin.Context) {
	role := c.GetString("role")

	if role != string(database.RoleAdmin) && role != string(database.RoleSuperAdmin) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied: Admin only"})
		return
	}

	var logs []database.AuditLog
	query := database.DB.Order("created_at desc").Limit(100)

	// [新增] 权限过滤逻辑
	if role == string(database.RoleAdmin) {
		// 组管理员：只能看自己组的日志
		// 注意：系统级日志(GroupID为nil) 对组管理员不可见
		groupID := c.GetUint("groupID")
		if groupID == 0 {
			// 如果 Admin 没有分配组，则看不到任何日志
			c.JSON(http.StatusOK, []database.AuditLog{})
			return
		}
		query = query.Where("group_id = ?", groupID)
	}
	// 超级管理员：可以看到所有日志 (不做 where 过滤)

	query.Find(&logs)

	c.JSON(http.StatusOK, logs)
}
