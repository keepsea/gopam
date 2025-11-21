package auth

import (
	"bytes"
	"image/png"
	"time"

	"github.com/pquerna/otp/totp"
)

// GenerateTOTPSecret 为用户生成新的 TOTP 密钥
// accountName: 用户名，显示在 Google Authenticator APP 中
// issuer: 发行方名称，如 "LitePAM"
// 返回: secret(存数据库), qrCodePng(展示给前端), url(备用), error
func GenerateTOTPSecret(accountName string, issuer string) (string, []byte, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
	})
	if err != nil {
		return "", nil, "", err
	}

	// 生成二维码图片
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		return "", nil, "", err
	}
	if err := png.Encode(&buf, img); err != nil {
		return "", nil, "", err
	}

	return key.Secret(), buf.Bytes(), key.URL(), nil
}

// ValidateTOTP 验证用户输入的 6 位动态码
// passcode: 用户输入的 123456
// secret: 数据库中存储的用户密钥
func ValidateTOTP(passcode string, secret string) bool {
	// 验证当前时间窗口的 code，允许前后 1 个周期的容差 (即允许 30 秒的时钟偏差)
	valid := totp.Validate(passcode, secret)
	return valid
}

// GenerateCode 仅用于测试或特殊场景：生成当前时间的 Code
func GenerateCode(secret string) (string, error) {
	return totp.GenerateCode(secret, time.Now())
}
