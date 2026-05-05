package handlers

import (
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

// HubConn is the abstraction the hub uses to talk to a peer.
// Production type (real WebSocket) implements this; tests use fakeConn.
type HubConn interface {
	DeviceID() int64
	UserID() string
	WriteFrame(b []byte) error
	Close()
}

type roomState struct {
	mu    sync.RWMutex
	peers map[HubConn]struct{}
}

// Hub is the in-memory registry of per-file collab rooms.
type Hub struct {
	mu    sync.RWMutex
	rooms map[string]*roomState // keyed by file_id
	db    *pgxpool.Pool         // nil in tests
}

// NewHub creates an empty Hub. db is used by future tasks for persistence; tests pass nil.
func NewHub(db *pgxpool.Pool) *Hub {
	return &Hub{rooms: map[string]*roomState{}, db: db}
}

// room returns (or lazily creates) the room state for a file.
func (h *Hub) room(fileID string) *roomState {
	h.mu.Lock()
	defer h.mu.Unlock()
	r, ok := h.rooms[fileID]
	if !ok {
		r = &roomState{peers: map[HubConn]struct{}{}}
		h.rooms[fileID] = r
	}
	return r
}

// Join adds a connection to the file's room.
func (h *Hub) Join(fileID string, c HubConn) {
	r := h.room(fileID)
	r.mu.Lock()
	r.peers[c] = struct{}{}
	r.mu.Unlock()
}

// Leave removes a connection from the file's room. Cleans up the room if empty.
func (h *Hub) Leave(fileID string, c HubConn) {
	r := h.room(fileID)
	r.mu.Lock()
	delete(r.peers, c)
	empty := len(r.peers) == 0
	r.mu.Unlock()
	if empty {
		h.mu.Lock()
		delete(h.rooms, fileID)
		h.mu.Unlock()
	}
}

// Peers returns a snapshot of the connections currently in a file's room.
func (h *Hub) Peers(fileID string) []HubConn {
	r := h.room(fileID)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]HubConn, 0, len(r.peers))
	for c := range r.peers {
		out = append(out, c)
	}
	return out
}

// Broadcast sends `frame` to every peer in the file's room except `sender`.
// WriteFrame errors are ignored at this layer — the conn is expected to handle
// disconnect/cleanup itself when its writePump fails.
func (h *Hub) Broadcast(fileID string, sender HubConn, frame []byte) {
	r := h.room(fileID)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for c := range r.peers {
		if c == sender {
			continue
		}
		_ = c.WriteFrame(frame)
	}
}

// CloseDevice forces all connections from a given device to close, across all rooms.
// Used when a device is revoked (Phase D5).
func (h *Hub) CloseDevice(deviceID int64) {
	h.mu.RLock()
	rooms := make([]*roomState, 0, len(h.rooms))
	for _, r := range h.rooms {
		rooms = append(rooms, r)
	}
	h.mu.RUnlock()
	for _, r := range rooms {
		r.mu.RLock()
		victims := []HubConn{}
		for c := range r.peers {
			if c.DeviceID() == deviceID {
				victims = append(victims, c)
			}
		}
		r.mu.RUnlock()
		for _, v := range victims {
			v.Close()
		}
	}
}
