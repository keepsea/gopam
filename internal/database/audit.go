package database

import (
	"encoding/json"
	"log"
)

// RecordAuditLog 记录一条审计日志
func RecordAuditLog(actor string, action string, target string, details interface{}) {
	// 将详情对象序列化为 JSON 字符串
	detailsJSON, _ := json.Marshal(details)

	entry := AuditLog{
		ActorName: actor,
		Action:    action,
		Target:    target,
		Details:   string(detailsJSON),
	}

	// 异步写入数据库，避免阻塞主业务流程
	go func() {
		if err := DB.Create(&entry).Error; err != nil {
			log.Printf("ERROR: Failed to write audit log: %v", err)
		}
	}()
}
