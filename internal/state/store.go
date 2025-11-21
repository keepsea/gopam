package state

import (
	"sync"
	"time"
)

// VaultManager 管理内存中的主密钥
type VaultManager struct {
	mu        sync.RWMutex
	dek       []byte    // 明文主密钥 (Data Encryption Key)
	expiresAt time.Time // 过期时间
}

var GlobalVault = &VaultManager{}

// Unlock 存入密钥并设置过期时间
func (v *VaultManager) Unlock(dek []byte, duration time.Duration) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.dek = dek
	v.expiresAt = time.Now().Add(duration)
}

// Lock 立即清除密钥
func (v *VaultManager) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.dek = nil
	v.expiresAt = time.Time{}
}

// GetDEK 获取密钥，如果过期或不存在则返回 nil
func (v *VaultManager) GetDEK() []byte {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if time.Now().After(v.expiresAt) || v.dek == nil {
		return nil
	}
	return v.dek
}

// IsUnlocked 检查是否解锁
func (v *VaultManager) IsUnlocked() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.dek != nil && time.Now().Before(v.expiresAt)
}
