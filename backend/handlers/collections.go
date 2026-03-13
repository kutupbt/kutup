package handlers

import (
	"context"

	"github.com/depo/backend/middleware"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CollectionsHandler struct {
	DB *pgxpool.Pool
}

func (h *CollectionsHandler) ListCollections(c *fiber.Ctx) error {
	userID := middleware.UserID(c)

	rows, err := h.DB.Query(context.Background(), `
		SELECT id, owner_user_id, encrypted_name, name_nonce,
		       encrypted_key, encrypted_key_nonce, parent_collection_id, color
		FROM collections WHERE owner_user_id = $1
		ORDER BY created_at ASC
	`, userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}
	defer rows.Close()

	type CollectionRow struct {
		ID                 string  `json:"id"`
		OwnerUserID        string  `json:"ownerUserId"`
		EncryptedName      string  `json:"encryptedName"`
		NameNonce          string  `json:"nameNonce"`
		EncryptedKey       string  `json:"encryptedKey"`
		EncryptedKeyNonce  string  `json:"encryptedKeyNonce"`
		ParentCollectionID *string `json:"parentCollectionId,omitempty"`
		Color              *string `json:"color,omitempty"`
	}

	var collections []CollectionRow
	for rows.Next() {
		var col CollectionRow
		if err := rows.Scan(
			&col.ID, &col.OwnerUserID, &col.EncryptedName, &col.NameNonce,
			&col.EncryptedKey, &col.EncryptedKeyNonce, &col.ParentCollectionID, &col.Color,
		); err != nil {
			continue
		}
		collections = append(collections, col)
	}

	// Also include collections shared with this user
	sharedRows, err := h.DB.Query(context.Background(), `
		SELECT c.id, c.owner_user_id, c.encrypted_name, c.name_nonce,
		       c.encrypted_key, c.encrypted_key_nonce, c.parent_collection_id, c.color,
		       cs.encrypted_collection_key, cs.can_write
		FROM collections c
		JOIN collection_shares cs ON cs.collection_id = c.id
		WHERE cs.recipient_user_id = $1
		ORDER BY c.created_at ASC
	`, userID)
	if err == nil {
		defer sharedRows.Close()
		for sharedRows.Next() {
			var col CollectionRow
			var sharedKey string
			var canWrite bool
			if err := sharedRows.Scan(
				&col.ID, &col.OwnerUserID, &col.EncryptedName, &col.NameNonce,
				&col.EncryptedKey, &col.EncryptedKeyNonce, &col.ParentCollectionID, &col.Color,
				&sharedKey, &canWrite,
			); err != nil {
				continue
			}
			// For shared collections, override the key with the recipient-specific one
			col.EncryptedKey = sharedKey
			collections = append(collections, col)
		}
	}

	if collections == nil {
		collections = []CollectionRow{}
	}
	return c.JSON(collections)
}

func (h *CollectionsHandler) CreateCollection(c *fiber.Ctx) error {
	userID := middleware.UserID(c)

	var req struct {
		EncryptedName      string  `json:"encryptedName"`
		NameNonce          string  `json:"nameNonce"`
		EncryptedKey       string  `json:"encryptedKey"`
		EncryptedKeyNonce  string  `json:"encryptedKeyNonce"`
		ParentCollectionID *string `json:"parentCollectionId"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}

	var id string
	err := h.DB.QueryRow(context.Background(), `
		INSERT INTO collections (owner_user_id, encrypted_name, name_nonce,
		                         encrypted_key, encrypted_key_nonce, parent_collection_id)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id
	`, userID, req.EncryptedName, req.NameNonce,
		req.EncryptedKey, req.EncryptedKeyNonce, req.ParentCollectionID,
	).Scan(&id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	return c.Status(201).JSON(fiber.Map{"id": id})
}

func (h *CollectionsHandler) GetCollection(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	collID := c.Params("id")

	var col struct {
		ID                 string  `json:"id"`
		OwnerUserID        string  `json:"ownerUserId"`
		EncryptedName      string  `json:"encryptedName"`
		NameNonce          string  `json:"nameNonce"`
		EncryptedKey       string  `json:"encryptedKey"`
		EncryptedKeyNonce  string  `json:"encryptedKeyNonce"`
		ParentCollectionID *string `json:"parentCollectionId,omitempty"`
		Color              *string `json:"color,omitempty"`
	}

	err := h.DB.QueryRow(context.Background(), `
		SELECT id, owner_user_id, encrypted_name, name_nonce,
		       encrypted_key, encrypted_key_nonce, parent_collection_id, color
		FROM collections
		WHERE id = $1 AND owner_user_id = $2
	`, collID, userID).Scan(
		&col.ID, &col.OwnerUserID, &col.EncryptedName, &col.NameNonce,
		&col.EncryptedKey, &col.EncryptedKeyNonce, &col.ParentCollectionID, &col.Color,
	)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}

	return c.JSON(col)
}

func (h *CollectionsHandler) UpdateCollection(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	collID := c.Params("id")

	var req struct {
		EncryptedName string `json:"encryptedName"`
		NameNonce     string `json:"nameNonce"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}

	result, err := h.DB.Exec(context.Background(), `
		UPDATE collections SET encrypted_name = $1, name_nonce = $2, updated_at = NOW()
		WHERE id = $3 AND owner_user_id = $4
	`, req.EncryptedName, req.NameNonce, collID, userID)
	if err != nil || result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}

	return c.JSON(fiber.Map{"message": "updated"})
}

func (h *CollectionsHandler) UpdateCollectionColor(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	collID := c.Params("id")

	var req struct {
		Color *string `json:"color"`
	}
	c.BodyParser(&req)

	result, err := h.DB.Exec(context.Background(), `
		UPDATE collections SET color = $1, updated_at = NOW()
		WHERE id = $2 AND owner_user_id = $3
	`, req.Color, collID, userID)
	if err != nil || result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}

	return c.SendStatus(204)
}

func (h *CollectionsHandler) DeleteCollection(c *fiber.Ctx) error {
	userID := middleware.UserID(c)
	collID := c.Params("id")

	result, err := h.DB.Exec(context.Background(),
		`DELETE FROM collections WHERE id = $1 AND owner_user_id = $2`,
		collID, userID)
	if err != nil || result.RowsAffected() == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "not found"})
	}

	return c.SendStatus(204)
}

func (h *CollectionsHandler) ShareCollection(c *fiber.Ctx) error {
	sharerID := middleware.UserID(c)
	collID := c.Params("id")

	var req struct {
		RecipientUserID        string `json:"recipientUserId"`
		EncryptedCollectionKey string `json:"encryptedCollectionKey"` // crypto_box_sealed with recipient pubkey
		CanWrite               bool   `json:"canWrite"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}

	// Verify sharer owns this collection
	var ownerID string
	err := h.DB.QueryRow(context.Background(),
		`SELECT owner_user_id FROM collections WHERE id = $1`, collID,
	).Scan(&ownerID)
	if err != nil || ownerID != sharerID {
		return c.Status(403).JSON(fiber.Map{"error": "forbidden"})
	}

	_, err = h.DB.Exec(context.Background(), `
		INSERT INTO collection_shares (collection_id, sharer_user_id, recipient_user_id,
		                               encrypted_collection_key, can_write)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (collection_id, recipient_user_id)
		DO UPDATE SET encrypted_collection_key = $4, can_write = $5
	`, collID, sharerID, req.RecipientUserID, req.EncryptedCollectionKey, req.CanWrite)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "internal error"})
	}

	return c.Status(201).JSON(fiber.Map{"message": "shared"})
}
