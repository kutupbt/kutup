package utils

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID  string `json:"userId"`
	IsAdmin bool   `json:"isAdmin"`
	jwt.RegisteredClaims
}

func GenerateAccessToken(userID string, isAdmin bool, secret string) (string, error) {
	claims := Claims{
		UserID:  userID,
		IsAdmin: isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func GenerateRefreshToken(userID string, secret string) (string, error) {
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// GenerateSetupToken creates a short-lived token used during first-login setup.
func GenerateSetupToken(userID string, secret string) (string, error) {
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   "setup",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// ValidateSetupToken validates a setup token and returns the userID.
func ValidateSetupToken(tokenStr string, secret string) (string, error) {
	claims, err := ValidateToken(tokenStr, secret)
	if err != nil {
		return "", err
	}
	if claims.Subject != "setup" {
		return "", errors.New("not a setup token")
	}
	return claims.UserID, nil
}

// GeneratePreAuthToken creates a short-lived token used during TOTP challenge.
func GeneratePreAuthToken(userID string, secret string) (string, error) {
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   "pre-auth",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// ValidatePreAuthToken validates a pre-auth token and returns the userID.
func ValidatePreAuthToken(tokenStr string, secret string) (string, error) {
	claims, err := ValidateToken(tokenStr, secret)
	if err != nil {
		return "", err
	}
	if claims.Subject != "pre-auth" {
		return "", errors.New("not a pre-auth token")
	}
	return claims.UserID, nil
}

func ValidateToken(tokenStr string, secret string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}
