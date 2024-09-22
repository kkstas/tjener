package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kkstas/tjener/internal/model/user"
)

func base64URLEncode(data interface{}) (string, error) {
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString([]byte(dataJSON)), err

}

func CreateToken(u user.User) (string, error) {
	header, err := base64URLEncode(map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	})
	if err != nil {
		return "", fmt.Errorf("failed encoding header: %w", err)
	}

	claims, err := base64URLEncode(map[string]interface{}{
		"exp":  time.Now().Add(24 * time.Hour).Unix(),
		"user": u,
	})
	if err != nil {
		return "", fmt.Errorf("failed encoding claims: %w", err)
	}

	signature, err := createSignature(header, claims)
	if err != nil {
		return "", fmt.Errorf("failed creating signature: %w", err)
	}

	return fmt.Sprintf("%s.%s.%s", header, claims, signature), nil
}

func createSignature(header, payload string) (string, error) {
	secret := os.Getenv("TOKEN_SECRET")
	if secret == "" {
		return "", errors.New("env variable TOKEN_SECRET is empty")
	}

	signingInput := fmt.Sprintf("%s.%s", header, payload)
	h := hmac.New(sha256.New, []byte(secret))
	_, err := h.Write([]byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("error during writing hmac: %w", err)
	}

	signature := h.Sum(nil)
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	return encodedSignature, nil
}

func ValidateToken(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("invalid token structure for token" + token)
	}
	header := parts[0]
	claims := parts[1]
	signature := parts[2]

	newSignature, err := createSignature(header, claims)
	if err != nil {
		return fmt.Errorf("error during creating signature: %w", err)
	}

	if newSignature != signature {
		return errors.New("signatures are not the same")
	}

	return nil
}
