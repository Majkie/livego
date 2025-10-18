package livego

import (
	"encoding/json"
	"net/http"
	"time"
)

func (h *Handler) HandleStoreLoad(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowedError(w, "Method not allowed")
		return
	}

	var req StoreLoadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequestError(w, "Invalid request body", map[string]interface{}{
			"parse_error": err.Error(),
		})
		return
	}

	snapshots := make(map[string]StoreSnapshot)
	now := time.Now().Unix()

	for _, storeReq := range req.Stores {
		if err := validateStoreKey(storeReq.Key); err != nil {
			writeValidationError(w, "Invalid store key: "+err.Error(), map[string]interface{}{
				"store_key":        storeReq.Key,
				"validation_error": err.Error(),
			})
			return
		}

		factory, exists := h.stores[storeReq.Key]
		if !exists {
			writeComponentError(w, ErrorStoreNotFound, "Store not found: "+storeReq.Key, http.StatusNotFound, map[string]interface{}{
				"store_key": storeReq.Key,
			})
			return
		}

		store := factory(r.Context())

		if err := store.Authorize(r.Context()); err != nil {
			writeComponentError(w, ErrorStoreAuthorization, "Store access not authorized: "+err.Error(), http.StatusUnauthorized, map[string]interface{}{
				"store_key":  storeReq.Key,
				"auth_error": err.Error(),
			})
			return
		}

		var data map[string]interface{}
		var err error

		if len(storeReq.Keys) > 0 {
			data, err = store.LoadKeys(r.Context(), storeReq.Keys)
		} else {
			data, err = store.Load(r.Context())
		}

		if err != nil {
			writeComponentError(w, ErrorStoreLoad, "Failed to load store: "+err.Error(), http.StatusInternalServerError, map[string]interface{}{
				"store_key":      storeReq.Key,
				"loading_error":  err.Error(),
				"keys_requested": storeReq.Keys,
			})
			return
		}

		checksum := generateStoreChecksum(h.secret, storeReq.Key, data, now)

		snapshots[storeReq.Key] = StoreSnapshot{
			Key:      storeReq.Key,
			Data:     data,
			Checksum: checksum,
			LoadedAt: now,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(StoreLoadResponse{
		Stores: snapshots,
	})
}
