package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// DeriveKeyFromPassword 使用 PBKDF2 将口令转换为密钥 (KEK)
func DeriveKeyFromPassword(password string, salt []byte) []byte {
	// 迭代 100,000 次，生成 32 字节 (256 bit) 的密钥
	return pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
}

// GenerateRandomKey 生成随机的 32 字节 DEK
func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateRandomSalt 生成随机盐值
func GenerateRandomSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// WrapKey 使用 KEK 加密 DEK
func WrapKey(kek []byte, dek []byte) (string, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, dek, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// UnwrapKey 使用 KEK 解密 DEK
func UnwrapKey(kek []byte, encryptedDEK string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedDEK)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}
