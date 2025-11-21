package handlers

import (
	"gopam/internal/database"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ListGroups 获取所有设备组 (公开接口，供下拉选择)
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

// --- 以下为超级管理员专用接口 ---

func checkGroupSuperAdmin(c *gin.Context) bool {
	role := c.GetString("role")
	if role != string(database.RoleSuperAdmin) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied: Super Admin only"})
		return false
	}
	return true
}

// CreateGroup 创建设备组
func CreateGroup(c *gin.Context) {
	if !checkGroupSuperAdmin(c) {
		return
	}

	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	group := database.DeviceGroup{
		Name:        req.Name,
		Description: req.Description,
	}

	if err := database.DB.Create(&group).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create group (name might be duplicate)"})
		return
	}

	database.RecordAuditLog(c.GetString("actor_label"), "CREATE_GROUP", group.Name, nil)
	c.JSON(http.StatusCreated, gin.H{"message": "Group created successfully", "id": group.ID})
}

// UpdateGroup 修改设备组
func UpdateGroup(c *gin.Context) {
	if !checkGroupSuperAdmin(c) {
		return
	}
	id := c.Param("id")

	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := database.DB.Model(&database.DeviceGroup{}).Where("id = ?", id).Updates(map[string]interface{}{
		"name":        req.Name,
		"description": req.Description,
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update group"})
		return
	}

	database.RecordAuditLog(c.GetString("actor_label"), "UPDATE_GROUP", req.Name, nil)
	c.JSON(http.StatusOK, gin.H{"message": "Group updated successfully"})
}

// DeleteGroup 删除设备组 (安全删除)
func DeleteGroup(c *gin.Context) {
	if !checkGroupSuperAdmin(c) {
		return
	}
	id := c.Param("id")

	// 1. 检查是否有关联设备
	var devCount int64
	database.DB.Model(&database.Device{}).Where("group_id = ?", id).Count(&devCount)
	if devCount > 0 {
		c.JSON(http.StatusForbidden, gin.H{"error": "无法删除：该组下仍有设备，请先转移或删除设备"})
		return
	}

	// 2. 检查是否有关联管理员
	var adminCount int64
	database.DB.Model(&database.User{}).Where("managed_group_id = ?", id).Count(&adminCount)
	if adminCount > 0 {
		c.JSON(http.StatusForbidden, gin.H{"error": "无法删除：有管理员负责该组，请先修改管理员权限"})
		return
	}

	// 3. 执行删除
	if err := database.DB.Delete(&database.DeviceGroup{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete group"})
		return
	}

	database.RecordAuditLog(c.GetString("actor_label"), "DELETE_GROUP", "GroupID:"+id, nil)
	c.JSON(http.StatusOK, gin.H{"message": "Group deleted successfully"})
}
