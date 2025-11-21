package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

// Encrypt 保持向后兼容 (如果还有其他地方用)，但内部实现可以调用 Raw
// 它会将输入的字符串密钥进行 Hash 处理，确保长度为 32 字节
func Encrypt(masterKey string, plaintext string) (string, error) {
	key := hashKey(masterKey)
	return EncryptRaw(key, plaintext)
}

// Decrypt 保持向后兼容
// 它会将输入的字符串密钥进行 Hash 处理，确保长度为 32 字节
func Decrypt(masterKey string, encryptedData string) (string, error) {
	key := hashKey(masterKey)
	return DecryptRaw(key, encryptedData)
}

// [新增] EncryptRaw 直接使用 32 字节密钥进行加密
// 此函数假设传入的 key 已经是符合 AES-256 要求的 32 字节密钥 (例如从 Vault 获取的 DEK)
func EncryptRaw(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// 生成随机 Nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// 加密并将 Nonce 拼接到密文头部
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// [新增] DecryptRaw 直接使用 32 字节密钥进行解密
func DecryptRaw(key []byte, encryptedData string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	// 分离 Nonce 和 密文
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("decryption failed: invalid key or corrupted data")
	}

	return string(plaintext), nil
}

// hashKey 将任意长度的字符串转换为固定的 32 bytes (256 bits) 密钥
func hashKey(key string) []byte {
	hash := sha256.Sum256([]byte(key))
	return hash[:]
}
