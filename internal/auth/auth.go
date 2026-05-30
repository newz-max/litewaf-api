package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var ErrInvalidToken = errors.New("invalid token")

type Claims struct {
	Subject   string `json:"sub"`
	UserID    int64  `json:"uid"`
	Role      string `json:"role"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func VerifyPassword(hash string, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func IssueToken(secret string, subject string, userID int64, role string, ttl time.Duration) (string, time.Time, error) {
	now := time.Now().UTC()
	expires := now.Add(ttl)
	claims := Claims{
		Subject:   subject,
		UserID:    userID,
		Role:      role,
		IssuedAt:  now.Unix(),
		ExpiresAt: expires.Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, err
	}
	payloadPart := base64.RawURLEncoding.EncodeToString(payload)
	sig := sign(secret, payloadPart)
	return payloadPart + "." + sig, expires, nil
}

func ParseToken(secret string, token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return Claims{}, ErrInvalidToken
	}
	expected := sign(secret, parts[0])
	if !hmac.Equal([]byte(expected), []byte(parts[1])) {
		return Claims{}, ErrInvalidToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, ErrInvalidToken
	}
	if claims.Subject == "" || claims.UserID <= 0 || claims.Role == "" {
		return Claims{}, ErrInvalidToken
	}
	if time.Now().UTC().Unix() > claims.ExpiresAt {
		return Claims{}, ErrInvalidToken
	}
	return claims, nil
}

func sign(secret string, payload string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TokenID(userID int64) string {
	return strconv.FormatInt(userID, 10)
}

func AuthorizationHeader(token string) string {
	return fmt.Sprintf("Bearer %s", token)
}
