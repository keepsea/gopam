package database

import (
	"testing"

	"gorm.io/gorm"
)

// setupTestDB 创建一个临时的内存数据库用于测试
func setupTestDB() *gorm.DB {
	// 使用 :memory: 模式，测试结束后数据自动销毁
	InitDB(":memory:")
	return DB
}

func TestV2Requirements(t *testing.T) {
	db := setupTestDB()

	// 1. 创建两个设备组 (模拟分权)
	networkGroup := DeviceGroup{Name: "Network-Zone", Description: "Firewalls and Switches"}
	serverGroup := DeviceGroup{Name: "Server-Zone", Description: "Linux Servers"}
	db.Create(&networkGroup)
	db.Create(&serverGroup)

	// 2. 创建角色
	// Admin-Net: 只管理 Network-Zone
	adminNet := User{
		Username:       "admin_net",
		PasswordHash:   "hash_123",
		Role:           RoleAdmin,
		ManagedGroupID: &networkGroup.ID, // 绑定权限
	}
	db.Create(&adminNet)

	// User-Ops: 普通运维
	userOps := User{
		Username:     "ops_wang",
		PasswordHash: "hash_456",
		Role:         RoleUser,
	}
	db.Create(&userOps)

	// 3. 模拟: 运维人员录入一台防火墙，归属 Network-Zone
	fwDevice := Device{
		Name:              "Core-FW-01",
		IP:                "192.168.1.1",
		Status:            StatusSafe,
		EncryptedPassword: "MOCKED_ENCRYPTED_PWD",
		GroupID:           networkGroup.ID, // 归属网络组
		CreatedByID:       userOps.ID,      // 王运维录入
	}
	if err := db.Create(&fwDevice).Error; err != nil {
		t.Fatalf("Failed to create device: %v", err)
	}

	// 4. 验证逻辑: admin_net 是否有权管理这台设备？
	// 查询 admin_net 管理的组下的所有设备
	var managedDevices []Device
	db.Where("group_id = ?", *adminNet.ManagedGroupID).Find(&managedDevices)

	if len(managedDevices) != 1 {
		t.Errorf("Admin Net should see exactly 1 device, found %d", len(managedDevices))
	}
	if managedDevices[0].Name != "Core-FW-01" {
		t.Errorf("Admin Net found wrong device: %s", managedDevices[0].Name)
	}

	// 5. 验证逻辑: 反例，如果有一个 admin_server，他能看到这台防火墙吗？
	// Admin-Server: 只管理 Server-Zone
	adminServer := User{
		Username:       "admin_server",
		PasswordHash:   "hash_789",
		Role:           RoleAdmin,
		ManagedGroupID: &serverGroup.ID,
	}
	db.Create(&adminServer)

	var serverDevices []Device
	db.Where("group_id = ?", *adminServer.ManagedGroupID).Find(&serverDevices)
	if len(serverDevices) != 0 {
		t.Errorf("Admin Server should see 0 devices, found %d", len(serverDevices))
	}
}
