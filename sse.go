package livego

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type StreamEvent struct {
	Event string         `json:"event"`
	Data  map[string]any `json:"data"`
	ID    string         `json:"id,omitempty"`
}

type StreamContext struct {
	componentID string
	manager     *StreamManager
	ctx         context.Context
}

func (sc *StreamContext) Stream(event string, data map[string]interface{}) error {
	return sc.manager.SendEvent(sc.componentID, StreamEvent{
		Event: event,
		Data:  data,
		ID:    sc.manager.generateEventID(),
	})
}

type StreamComponent interface {
	Component
	OnStream(ctx *StreamContext) error
}

type StreamManager struct {
	mu          sync.RWMutex
	connections map[string]map[string]*streamConnection // componentID -> connectionID -> connection
	secret      string
}

type streamConnection struct {
	id       string
	w        http.ResponseWriter
	flusher  http.Flusher
	ctx      context.Context
	cancel   context.CancelFunc
	lastPing time.Time
	mu       sync.Mutex
}

func NewStreamManager(secret string) *StreamManager {
	sm := &StreamManager{
		connections: make(map[string]map[string]*streamConnection),
		secret:      secret,
	}

	// Start cleanup routine
	go sm.cleanupRoutine()

	return sm
}

func (sm *StreamManager) HandleStream(w http.ResponseWriter, r *http.Request) {
	// Verify this is an SSE request
	if r.Header.Get("Accept") != "text/event-stream" {
		writeValidationError(w, "Invalid Accept header for SSE", nil)
		return
	}

	componentID := r.URL.Query().Get("component_id")
	if componentID == "" {
		writeBadRequestError(w, "Missing component_id", nil)
		return
	}

	// Verify component signature to prevent unauthorized streaming
	signature := r.URL.Query().Get("signature")
	if !sm.verifyStreamSignature(componentID, signature) {
		writeUnauthorizedError(w, "Invalid stream signature", nil)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // Disable nginx buffering

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeInternalServerError(w, "Streaming not supported", nil)
		return
	}

	// Create connection context
	ctx, cancel := context.WithCancel(r.Context())
	connID := sm.generateConnectionID()

	conn := &streamConnection{
		id:       connID,
		w:        w,
		flusher:  flusher,
		ctx:      ctx,
		cancel:   cancel,
		lastPing: time.Now(),
	}

	// Register connection
	sm.addConnection(componentID, conn)
	defer sm.removeConnection(componentID, connID)

	// Send initial connection event
	sm.writeEvent(conn, StreamEvent{
		Event: "connected",
		Data: map[string]interface{}{
			"component_id":  componentID,
			"connection_id": connID,
		},
		ID: sm.generateEventID(),
	})

	// Keep connection alive with periodic pings
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if err := sm.ping(conn); err != nil {
				return
			}
		}
	}
}

func (sm *StreamManager) SendEvent(componentID string, event StreamEvent) error {
	sm.mu.RLock()
	connections, exists := sm.connections[componentID]
	sm.mu.RUnlock()

	if !exists || len(connections) == 0 {
		return fmt.Errorf("no active connections for component %s", componentID)
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(connections))

	for _, conn := range connections {
		wg.Add(1)
		go func(c *streamConnection) {
			defer wg.Done()
			if err := sm.writeEvent(c, event); err != nil {
				errChan <- err
			}
		}(conn)
	}

	wg.Wait()
	close(errChan)

	// Return first error if any
	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}

func (sm *StreamManager) ping(conn *streamConnection) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if _, err := fmt.Fprintf(conn.w, ": ping\n\n"); err != nil {
		return err
	}

	conn.flusher.Flush()
	conn.lastPing = time.Now()
	return nil
}

// addConnection registers a new connection
func (sm *StreamManager) addConnection(componentID string, conn *streamConnection) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.connections[componentID] == nil {
		sm.connections[componentID] = make(map[string]*streamConnection)
	}

	sm.connections[componentID][conn.id] = conn
}

// removeConnection unregisters a connection
func (sm *StreamManager) removeConnection(componentID, connID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if connections, exists := sm.connections[componentID]; exists {
		if conn, exists := connections[connID]; exists {
			conn.cancel()
			delete(connections, connID)
		}

		if len(connections) == 0 {
			delete(sm.connections, componentID)
		}
	}
}

func (sm *StreamManager) writeEvent(conn *streamConnection, event StreamEvent) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	select {
	case <-conn.ctx.Done():
		return fmt.Errorf("connection closed")
	default:
	}

	data, err := json.Marshal(event.Data)
	if err != nil {
		return err
	}

	// SSE format: event: eventName\ndata: jsonData\nid: eventId\n\n
	if event.Event != "" {
		if _, err := fmt.Fprintf(conn.w, "event: %s\n", event.Event); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(conn.w, "data: %s\n", data); err != nil {
		return err
	}

	if event.ID != "" {
		if _, err := fmt.Fprintf(conn.w, "id: %s\n", event.ID); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(conn.w, "\n"); err != nil {
		return err
	}

	conn.flusher.Flush()
	conn.lastPing = time.Now()

	return nil
}

func (sm *StreamManager) cleanupRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		sm.mu.Lock()
		cutoff := time.Now().Add(-60 * time.Second)

		for componentID, connections := range sm.connections {
			for connID, conn := range connections {
				if conn.lastPing.Before(cutoff) {
					conn.cancel()
					delete(connections, connID)
				}
			}

			if len(connections) == 0 {
				delete(sm.connections, componentID)
			}
		}
		sm.mu.Unlock()
	}
}

func (sm *StreamManager) generateConnectionID() string {
	bytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		panic("failed to generate connection ID")
	}
	return hex.EncodeToString(bytes)
}

func (sm *StreamManager) generateEventID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func (sm *StreamManager) verifyStreamSignature(componentID, signature string) bool {
	// Generate expected signature
	mac := hmac.New(sha256.New, []byte(sm.secret))
	mac.Write([]byte(componentID))
	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(signature))
}

func (sm *StreamManager) GenerateStreamSignature(componentID string) string {
	mac := hmac.New(sha256.New, []byte(sm.secret))
	mac.Write([]byte(componentID))
	return hex.EncodeToString(mac.Sum(nil))
}
