package database

import (
	"encoding/json"
	"log"
)

// RecordAuditLog 记录一条审计日志
// [修改] 增加 groupID 参数，传入 nil 表示系统级日志(仅超管可见)
func RecordAuditLog(actor string, action string, target string, details interface{}, groupID *uint) {
	// 将详情对象序列化为 JSON 字符串
	detailsJSON, _ := json.Marshal(details)

	entry := AuditLog{
		ActorName: actor,
		Action:    action,
		Target:    target,
		Details:   string(detailsJSON),
		GroupID:   groupID, // 记录归属组
	}

	// 异步写入数据库
	go func() {
		if err := DB.Create(&entry).Error; err != nil {
			log.Printf("ERROR: Failed to write audit log: %v", err)
		}
	}()
}
