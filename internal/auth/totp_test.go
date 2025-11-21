package auth

import (
	"testing"
)

func TestTOTPFlow(t *testing.T) {
	user := "admin_test"
	issuer := "LitePAM-Test"

	// 1. 生成密钥 (模拟用户绑定 MFA)
	secret, qrPng, url, err := GenerateTOTPSecret(user, issuer)
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	if secret == "" || len(qrPng) == 0 || url == "" {
		t.Fatal("Generated secret/QR/URL should not be empty")
	}
	t.Logf("Generated Secret: %s", secret)

	// 2. 生成当前有效的 Code (模拟手机 APP 生成)
	validCode, err := GenerateCode(secret)
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}
	t.Logf("Current Code: %s", validCode)

	// 3. 验证成功的场景
	if !ValidateTOTP(validCode, secret) {
		t.Fatal("Valid code was rejected by validator")
	}

	// 4. 验证失败的场景 (错误的 Code)
	wrongCode := "000000"
	if ValidateTOTP(wrongCode, secret) {
		t.Fatal("Invalid code was accepted by validator")
	}

	// 5. 验证失败的场景 (错误的 Secret)
	wrongSecret := "JBSWY3DPEHPK3PXP" // base32 format
	if ValidateTOTP(validCode, wrongSecret) {
		t.Fatal("Code accepted with wrong secret")
	}
}
