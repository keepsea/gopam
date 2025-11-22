package database

import (
	"time"

	"gorm.io/gorm"
)

// --- Enums ---

type UserRole string
type DeviceStatus string
type RequestStatus string

const (
	RoleSuperAdmin UserRole = "SUPER_ADMIN" // [新增] 超级管理员：管人、管组
	RoleAdmin      UserRole = "ADMIN"       // 组管理员：管设备、审批
	RoleUser       UserRole = "USER"        // 运维人员：申请、使用

	StatusSafe            DeviceStatus = "SAFE"
	StatusPendingApproval DeviceStatus = "PENDING_APPROVAL"
	StatusApproved        DeviceStatus = "APPROVED"
	StatusInUse           DeviceStatus = "IN_USE"
	StatusPendingReset    DeviceStatus = "PENDING_RESET"

	ReqStatusPending   RequestStatus = "PENDING"
	ReqStatusApproved  RequestStatus = "APPROVED"
	ReqStatusRejected  RequestStatus = "REJECTED"
	ReqStatusCompleted RequestStatus = "COMPLETED"
)

// --- Models ---

// [新增] 系统配置表 (存储加密后的主密钥)
type SystemConfig struct {
	ConfigKey    string `gorm:"primaryKey"` // 固定值: "MASTER_DEK"
	EncryptedDEK string `gorm:"not null"`   // 被口令加密后的 Data Encryption Key
	Salt         string `gorm:"not null"`   // PBKDF2 盐值
	UpdatedAt    time.Time
}

// DeviceGroup 设备组
type DeviceGroup struct {
	gorm.Model
	Name        string `gorm:"uniqueIndex;not null"`
	Description string
	Devices     []Device `gorm:"foreignKey:GroupID"`
	Admins      []User   `gorm:"foreignKey:ManagedGroupID"`
}

// User 用户表
type User struct {
	gorm.Model
	Username     string   `gorm:"uniqueIndex;not null"`
	PasswordHash string   `gorm:"not null"`
	Role         UserRole `gorm:"default:'USER'"`

	// [新增] 实名与联系方式
	RealName    string
	ContactInfo string

	TOTPSecret string

	// RBAC/Scope
	ManagedGroupID *uint
	ManagedGroup   *DeviceGroup `gorm:"foreignKey:ManagedGroupID"`
}

// Device 设备资产表
type Device struct {
	gorm.Model
	Name              string `gorm:"not null"`
	IP                string `gorm:"not null"`
	Protocol          string
	Status            DeviceStatus `gorm:"default:'SAFE'"`
	EncryptedPassword string       `gorm:"not null"`

	GroupID uint
	Group   DeviceGroup `gorm:"foreignKey:GroupID"`

	CreatedByID uint
	CreatedBy   User `gorm:"foreignKey:CreatedByID"`
}

// Request 借用申请单
type Request struct {
	gorm.Model
	DeviceID uint
	Device   Device `gorm:"foreignKey:DeviceID"`

	UserID uint
	User   User `gorm:"foreignKey:UserID"`

	ApproverID *uint
	Approver   *User `gorm:"foreignKey:ApproverID"`

	Reason     string
	Duration   string
	Status     RequestStatus `gorm:"default:'PENDING'"`
	ApprovedAt *time.Time
}

// AuditLog 审计日志
type AuditLog struct {
	gorm.Model
	ActorName string
	Action    string
	Target    string
	Details   string
	GroupID   *uint `gorm:"index"` // 新增: 用于权限隔离，可为空(系统级日志)
}
