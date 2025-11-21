package handlers

import (
	"gopam/internal/database"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ListGroups 获取所有设备组 (供运维录入设备时选择归属)
func ListGroups(c *gin.Context) {
	var groups []database.DeviceGroup
	// 仅返回 ID 和 Name，减少数据传输
	result := database.DB.Select("id", "name", "description").Find(&groups)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch groups"})
		return
	}

	c.JSON(http.StatusOK, groups)
}
