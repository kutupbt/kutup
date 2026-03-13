package middleware

import "github.com/gofiber/fiber/v2"

func AdminRequired() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !IsAdmin(c) {
			return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
		}
		return c.Next()
	}
}
