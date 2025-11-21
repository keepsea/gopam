package auth

import (
	"errors"
	"gopam/internal/database"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// 系统 JWT 签名密钥 (生产环境应从环境变量读取)
var jwtSecret = []byte("system-jwt-secret-key-change-me")

type Claims struct {
	UserID         uint   `json:"uid"`
	Username       string `json:"sub"`
	Role           string `json:"role"`
	ManagedGroupID *uint  `json:"gid,omitempty"` // Admin 的管辖范围
	jwt.RegisteredClaims
}

// GenerateToken 为登录用户签发 JWT
func GenerateToken(user database.User) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)

	claims := &Claims{
		UserID:         user.ID,
		Username:       user.Username,
		Role:           string(user.Role),
		ManagedGroupID: user.ManagedGroupID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    "LitePAM",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// ParseToken 验证并解析 Token
func ParseToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
