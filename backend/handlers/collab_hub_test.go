package handlers

import (
	"sync"
	"sync/atomic"
	"testing"
)

type fakeConn struct {
	deviceID int64
	userID   string
	written  atomic.Int64
}

func (f *fakeConn) DeviceID() int64           { return f.deviceID }
func (f *fakeConn) UserID() string             { return f.userID }
func (f *fakeConn) WriteFrame(b []byte) error  { f.written.Add(1); return nil }
func (f *fakeConn) Close()                     {}

func TestHubAddRemove(t *testing.T) {
	h := NewHub(nil)
	c1 := &fakeConn{deviceID: 1, userID: "u1"}
	c2 := &fakeConn{deviceID: 2, userID: "u2"}

	h.Join("file-A", c1)
	h.Join("file-A", c2)
	if got := h.Peers("file-A"); len(got) != 2 {
		t.Fatalf("want 2 peers, got %d", len(got))
	}

	h.Leave("file-A", c1)
	if got := h.Peers("file-A"); len(got) != 1 {
		t.Fatalf("want 1 peer after leave, got %d", len(got))
	}
}

func TestHubBroadcastSkipsSender(t *testing.T) {
	h := NewHub(nil)
	c1 := &fakeConn{deviceID: 1}
	c2 := &fakeConn{deviceID: 2}
	h.Join("f", c1)
	h.Join("f", c2)
	h.Broadcast("f", c1, []byte("data"))
	if c1.written.Load() != 0 {
		t.Fatalf("sender should not receive its own broadcast")
	}
	if c2.written.Load() != 1 {
		t.Fatalf("peer should receive broadcast, got %d", c2.written.Load())
	}
}

func TestHubCloseDevice(t *testing.T) {
	h := NewHub(nil)
	c1 := &fakeConn{deviceID: 1}
	c2 := &fakeConn{deviceID: 2}
	h.Join("f1", c1)
	h.Join("f2", c2)
	h.Join("f3", c1) // device 1 in two rooms

	h.CloseDevice(1)
	// CloseDevice calls Close() on victim conns; the test fake's Close is a no-op,
	// so we can't observe a state change directly. Smoke check: doesn't panic, doesn't
	// mutate the rooms map (Leave is the conn's own responsibility).
	if got := h.Peers("f2"); len(got) != 1 {
		t.Fatalf("device 2 should still be in f2, got %d", len(got))
	}
}

func TestHubConcurrency(t *testing.T) {
	h := NewHub(nil)
	const G, N = 16, 500
	files := []string{"f1", "f2", "f3"}
	var wg sync.WaitGroup
	for g := 0; g < G; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c := &fakeConn{deviceID: int64(id)}
			for i := 0; i < N; i++ {
				f := files[(id+i)%len(files)]
				h.Join(f, c)
				_ = h.Peers(f)
				h.Broadcast(f, c, []byte("x"))
				h.Leave(f, c)
			}
		}(g)
	}
	wg.Wait()
}
