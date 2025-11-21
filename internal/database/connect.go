package database

import (
	"log"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// InitDB 初始化 SQLite 连接并自动迁移 Schema
// dbPath: 数据库文件路径，如 "lite-pam.db"
func InitDB(dbPath string) error {
	var err error
	// 使用 SQLite 驱动，并开启 GORM 日志
	DB, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return err
	}

	// 强制开启 SQLite 外键约束
	DB.Exec("PRAGMA foreign_keys = ON")

	// 自动迁移: 根据 Struct 创建/更新表结构
	// [修复] 必须将 SystemConfig 加入列表，否则不会创建表
	err = DB.AutoMigrate(
		&SystemConfig{}, // [新增]
		&DeviceGroup{},
		&User{},
		&Device{},
		&Request{},
		&AuditLog{},
	)
	if err != nil {
		return err
	}

	log.Println("Database initialized and schema migrated.")
	return nil
}
