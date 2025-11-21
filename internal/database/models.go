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
	RoleAdmin UserRole = "ADMIN" // 组管理员
	RoleUser  UserRole = "USER"  // 运维人员

	StatusSafe            DeviceStatus = "SAFE"             // 在库安全
	StatusPendingApproval DeviceStatus = "PENDING_APPROVAL" // 待审批
	StatusApproved        DeviceStatus = "APPROVED"         // 待领取
	StatusInUse           DeviceStatus = "IN_USE"           // 使用中
	StatusPendingReset    DeviceStatus = "PENDING_RESET"    // 待重置

	ReqStatusPending   RequestStatus = "PENDING"
	ReqStatusApproved  RequestStatus = "APPROVED"
	ReqStatusRejected  RequestStatus = "REJECTED"
	ReqStatusCompleted RequestStatus = "COMPLETED"
)

// --- Models ---

// DeviceGroup 设备组 (管理边界)
type DeviceGroup struct {
	gorm.Model
	Name        string `gorm:"uniqueIndex;not null"`
	Description string
	// 关联: 一个组有多个设备
	Devices []Device `gorm:"foreignKey:GroupID"`
	// 关联: 一个组可能有多个管理员
	Admins []User `gorm:"foreignKey:ManagedGroupID"`
}

// User 用户表
type User struct {
	gorm.Model
	Username     string   `gorm:"uniqueIndex;not null"`
	PasswordHash string   `gorm:"not null"`
	Role         UserRole `gorm:"default:'USER'"`
	TOTPSecret   string   // 仅 Admin 需要

	// RBAC/Scope: 如果是 Admin，他管理哪个组？
	ManagedGroupID *uint        // Pointer 允许为 null (User 角色没有此字段)
	ManagedGroup   *DeviceGroup `gorm:"foreignKey:ManagedGroupID"`
}

// Device 设备资产表
type Device struct {
	gorm.Model
	Name              string       `gorm:"not null"`
	IP                string       `gorm:"not null"`
	Protocol          string       // SSH, RDP, etc.
	Status            DeviceStatus `gorm:"default:'SAFE'"`
	EncryptedPassword string       `gorm:"not null"` // AES-256 Base64

	// 归属哪个组 (决定谁能审批)
	GroupID uint
	Group   DeviceGroup `gorm:"foreignKey:GroupID"`

	// 谁录入的
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

	// 实际审批人 (必须是该 Device Group 的 Admin)
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
	ActorName string // 冗余存储用户名，防删除
	Action    string // LOGIN, APPLY, APPROVE...
	Target    string // 目标对象名称
	Details   string // JSON 格式详情
}
