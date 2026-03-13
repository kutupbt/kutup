package middleware

import (
	"strings"

	"github.com/depo/backend/utils"
	"github.com/gofiber/fiber/v2"
)

type AuthMiddleware struct {
	JWTSecret string
}

func NewAuth(secret string) *AuthMiddleware {
	return &AuthMiddleware{JWTSecret: secret}
}

func (a *AuthMiddleware) Required() fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenStr := extractToken(c)
		if tokenStr == "" {
			return c.Status(401).JSON(fiber.Map{"error": "unauthorized"})
		}
		claims, err := utils.ValidateToken(tokenStr, a.JWTSecret)
		if err != nil {
			return c.Status(401).JSON(fiber.Map{"error": "unauthorized"})
		}
		c.Locals("userId", claims.UserID)
		c.Locals("isAdmin", claims.IsAdmin)
		return c.Next()
	}
}

func extractToken(c *fiber.Ctx) string {
	// Check Authorization header first
	auth := c.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

func UserID(c *fiber.Ctx) string {
	id, _ := c.Locals("userId").(string)
	return id
}

func IsAdmin(c *fiber.Ctx) bool {
	v, _ := c.Locals("isAdmin").(bool)
	return v
}
