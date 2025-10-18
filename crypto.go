package livego

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Cryptographic functions for component and store security

// generateChecksum creates an HMAC checksum for component state and memo
func generateChecksum(secret string, state map[string]interface{}, memo ComponentMemo) string {
	mac := hmac.New(sha256.New, []byte(secret))

	// Write state directly to HMAC to avoid string concatenation
	stateJSON, _ := json.Marshal(state)
	mac.Write(stateJSON)

	// Write memo directly to HMAC
	memoJSON, _ := json.Marshal(memo)
	mac.Write(memoJSON)

	return hex.EncodeToString(mac.Sum(nil))
}

// verifyChecksum validates a component snapshot checksum
func verifyChecksum(secret string, snapshot ComponentSnapshot) bool {
	expected := generateChecksum(secret, snapshot.State, snapshot.Memo)
	return hmac.Equal([]byte(expected), []byte(snapshot.Checksum))
}

// generateTimedChecksum creates a checksum with timestamp for expiration
func generateTimedChecksum(secret string, state map[string]interface{}, memo EnhancedComponentMemo) string {
	stateJSON, _ := json.Marshal(state)
	memoJSON, _ := json.Marshal(memo)

	// Include timestamp in checksum
	data := fmt.Sprintf("%s|%s|%d", stateJSON, memoJSON, memo.MountedAt)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))

	return hex.EncodeToString(mac.Sum(nil))
}

// verifyTimedChecksum validates checksum and checks expiration
func verifyTimedChecksum(secret string, snapshot ComponentSnapshot, checksumLifetime time.Duration) bool {
	// Extract timestamp from memo
	var memo EnhancedComponentMemo
	memoJSON, _ := json.Marshal(snapshot.Memo)
	if err := json.Unmarshal(memoJSON, &memo); err != nil {
		return false
	}

	// Check if expired
	now := time.Now().Unix()
	age := time.Duration(now-memo.MountedAt) * time.Second
	if age > checksumLifetime {
		return false
	}

	expected := generateTimedChecksum(secret, snapshot.State, memo)
	return hmac.Equal([]byte(expected), []byte(snapshot.Checksum))
}

// signGlobalState creates a signed global state object
func signGlobalState(secret string, data map[string]interface{}) GlobalState {
	dataJSON, _ := json.Marshal(data)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(dataJSON)
	checksum := hex.EncodeToString(mac.Sum(nil))

	return GlobalState{
		Data:     data,
		Checksum: checksum,
	}
}

// verifyGlobalState verifies the global state signature
func verifyGlobalState(secret string, state GlobalState) bool {
	dataJSON, _ := json.Marshal(state.Data)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(dataJSON)
	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(state.Checksum))
}

// generateStoreChecksum creates a checksum for store data
func generateStoreChecksum(secret string, key string, data map[string]interface{}, timestamp int64) string {
	dataJSON, _ := json.Marshal(data)
	payload := fmt.Sprintf("%s|%s|%d", key, dataJSON, timestamp)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}
