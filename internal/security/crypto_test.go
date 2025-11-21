package security

import (
	"testing"
)

func TestEncryptDecryptFlow(t *testing.T) {
	masterKey := "my-super-secret-system-key-2025"
	originalText := "Initial_Root_Password_123!"

	// 1. 测试加密
	encrypted, err := Encrypt(masterKey, originalText)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	t.Logf("Original: %s", originalText)
	t.Logf("Encrypted (Base64): %s", encrypted)

	if encrypted == originalText {
		t.Fatal("Encrypted text should not match original text")
	}

	// 2. 测试解密
	decrypted, err := Decrypt(masterKey, encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != originalText {
		t.Fatalf("Decrypted text '%s' does not match original '%s'", decrypted, originalText)
	}
}

func TestRandomness(t *testing.T) {
	masterKey := "test-key"
	text := "same-password"

	// 即使明文相同，由于随机 Nonce 的存在，密文必须不同
	enc1, _ := Encrypt(masterKey, text)
	enc2, _ := Encrypt(masterKey, text)

	if enc1 == enc2 {
		t.Fatal("Security flaw: Same text produced same ciphertext (Nonce not random?)")
	}
}

func TestTamperProtection(t *testing.T) {
	masterKey := "correct-key"
	wrongKey := "wrong-key-attacker"
	text := "secret-data"

	encrypted, _ := Encrypt(masterKey, text)

	// 1. 使用错误密钥解密
	_, err := Decrypt(wrongKey, encrypted)
	if err == nil {
		t.Fatal("Security flaw: Decryption succeeded with wrong key")
	} else {
		t.Logf("Expected error with wrong key: %v", err)
	}

	// 2. 篡改密文 (修改 Base64 字符串的一个字符)
	// 注意：这里简单修改末尾字符可能导致 base64 格式错误，也可能导致 GCM 校验错误，都算测试通过
	tampered := encrypted[:len(encrypted)-1] + "A"
	_, err2 := Decrypt(masterKey, tampered)
	if err2 == nil {
		t.Fatal("Security flaw: Decryption succeeded with tampered ciphertext")
	}
}
