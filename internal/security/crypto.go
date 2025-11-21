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

// Encrypt 使用 AES-256-GCM 算法加密数据
// masterKey: 系统主密钥（建议通过环境变量传入，任意长度，内部会做 Hash 处理）
// plaintext: 需要加密的敏感信息
func Encrypt(masterKey string, plaintext string) (string, error) {
	// 1. 处理密钥：确保密钥长度为 32 bytes (256 bits)
	key := hashKey(masterKey)

	// 2. 创建 Cipher Block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// 3. 使用 GCM (Galois/Counter Mode) 模式，它同时提供加密和完整性校验
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// 4. 生成随机 Nonce (IV)，标准长度为 12 bytes
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// 5. 加密：Seal 函数会将 nonce, ciphertext, authentication tag 组合在一起
	// 格式: [Nonce] + [Ciphertext + Tag]
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)

	// 6. 返回 Base64 字符串以便存储
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt 使用 AES-256-GCM 算法解密数据
// masterKey: 必须与加密时使用的密钥一致
// encryptedData: Base64 编码的密文
func Decrypt(masterKey string, encryptedData string) (string, error) {
	key := hashKey(masterKey)

	// 1. 解码 Base64
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	// 2. 创建 Cipher Block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// 3. 提取 Nonce 和 密文
	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// 4. 解密：Open 函数会验证 Tag，如果被篡改会报错
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
