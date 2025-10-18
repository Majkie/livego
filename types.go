package livego

import (
	"context"
	"time"
)

// Component represents a LiveGo component with lifecycle methods
type Component interface {
	Mount() error
	Hydrate(state map[string]interface{}) error
	Dehydrate() map[string]interface{}
	GetID() string
	SetID(id string)
}

// PageComponent represents a component that can provide data to children
type PageComponent interface {
	Component
	ProvideData() map[string]interface{}
}

// ChildComponent can consume data from parent
type ChildComponent interface {
	Component
	OnParentDataChange(data map[string]interface{})
}

// Authorization interfaces
type MountAuthorizer interface {
	AuthorizeMount(ctx context.Context) error
}

type UpdateAuthorizer interface {
	AuthorizeUpdate(ctx context.Context, updateType string, payload map[string]interface{}) error
}

// Store interface for data persistence
type Store interface {
	// Key returns the store identifier
	Key() string
	// Load returns the store data
	Load(ctx context.Context) (map[string]interface{}, error)
	// LoadKeys returns specific keys from the store
	LoadKeys(ctx context.Context, keys []string) (map[string]interface{}, error)
	// Authorize checks if the user can access this store
	Authorize(ctx context.Context) error
}

// Factory types
type ComponentFactory func(ctx context.Context) Component
type StoreFactory func(ctx context.Context) Store

// Request/Response types for mounting
type MountRequest struct {
	Component string                 `json:"component"`
	Props     map[string]interface{} `json:"props"`
}

type MountResponse struct {
	Snapshot ComponentSnapshot `json:"snapshot"`
}

// Request/Response types for page operations
type PageMountRequest struct {
	Components []ComponentMountRequest `json:"components"`
	Global     map[string]interface{}  `json:"global"`
}

type ComponentMountRequest struct {
	ID        string                 `json:"id"`
	Component string                 `json:"component"`
	Props     map[string]interface{} `json:"props"`
	ParentID  *string                `json:"parentId"`
}

type PageMountResponse struct {
	Components map[string]ComponentSnapshot `json:"components"`
	Global     GlobalState                  `json:"global"`
}

type PageUpdateRequest struct {
	Components map[string]ComponentSnapshot `json:"components"` // All current components
	Updates    []ComponentUpdateRequest     `json:"updates"`
	Global     GlobalState                  `json:"global"`
}

type ComponentUpdateRequest struct {
	ID      string   `json:"id"`
	Updates []Update `json:"updates"`
}

type PageUpdateResponse struct {
	Components map[string]ComponentSnapshot `json:"components"`
	Global     GlobalState                  `json:"global"`
}

// Update system types
type UpdateRequest struct {
	Snapshot ComponentSnapshot `json:"snapshot"`
	Updates  []Update          `json:"updates"`
	Token    string            `json:"_token"`
}

type Update struct {
	Type    string                 `json:"type"`
	Payload map[string]interface{} `json:"payload"`
}

type UpdateResponse struct {
	Snapshot ComponentSnapshot `json:"snapshot"`
	Effects  Effects           `json:"effects"`
}

type Effects struct {
	Dirty      []string                 `json:"dirty"`
	Dispatches []map[string]interface{} `json:"dispatches"`
	Redirects  *string                  `json:"redirects"`
	HTML       *string                  `json:"html"`
}

// Component snapshot and memo types
type ComponentSnapshot struct {
	State    map[string]interface{} `json:"state"`
	Memo     ComponentMemo          `json:"memo"`
	Checksum string                 `json:"checksum"`
}

type ComponentMemo struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Path     string                 `json:"path"`
	Method   string                 `json:"method"`
	Children []string               `json:"children"`
	Data     map[string]interface{} `json:"data"`
}

// Enhanced memo with relationships and timing
type EnhancedComponentMemo struct {
	ComponentMemo
	Relationship ComponentRelationship `json:"relationship"`
	MountedAt    int64                 `json:"mountedAt"` // Unix timestamp
}

type ComponentRelationship struct {
	ParentID *string  `json:"parentId"`
	Children []string `json:"children"`
}

// Global state with signature
type GlobalState struct {
	Data     map[string]interface{} `json:"data"`
	Checksum string                 `json:"checksum"`
}

// Store types
type StoreLoadRequest struct {
	Stores []StoreLoadItem `json:"stores"`
}

type StoreLoadItem struct {
	Key  string   `json:"key"`
	Keys []string `json:"keys"` // Optional: load specific keys only
}

type StoreLoadResponse struct {
	Stores map[string]StoreSnapshot `json:"stores"` // key -> snapshot
}

type StoreSnapshot struct {
	Key      string                 `json:"key"`
	Data     map[string]interface{} `json:"data"`
	Checksum string                 `json:"checksum"`
	LoadedAt int64                  `json:"loadedAt"`
}

// Error response structure
type ErrorResponse struct {
	Error   string                 `json:"error"`
	Message string                 `json:"message"`
	Code    int                    `json:"code"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// Error constants
const (
	// Client errors (4xx)
	ErrorBadRequest       = "BAD_REQUEST"
	ErrorUnauthorized     = "UNAUTHORIZED"
	ErrorForbidden        = "FORBIDDEN"
	ErrorNotFound         = "NOT_FOUND"
	ErrorMethodNotAllowed = "METHOD_NOT_ALLOWED"
	ErrorTooManyRequests  = "TOO_MANY_REQUESTS"
	ErrorValidation       = "VALIDATION_ERROR"

	// Server errors (5xx)
	ErrorInternalServer     = "INTERNAL_SERVER_ERROR"
	ErrorServiceUnavailable = "SERVICE_UNAVAILABLE"

	// Component specific errors
	ErrorComponentNotFound  = "COMPONENT_NOT_FOUND"
	ErrorComponentMount     = "COMPONENT_MOUNT_ERROR"
	ErrorComponentUpdate    = "COMPONENT_UPDATE_ERROR"
	ErrorComponentHydration = "COMPONENT_HYDRATION_ERROR"
	ErrorMethodExecution    = "METHOD_EXECUTION_ERROR"

	// Security errors
	ErrorChecksumMismatch = "CHECKSUM_MISMATCH"
	ErrorRateLimit        = "RATE_LIMIT_EXCEEDED"

	// Store errors
	ErrorStoreNotFound      = "STORE_NOT_FOUND"
	ErrorStoreLoad          = "STORE_LOAD_ERROR"
	ErrorStoreAuthorization = "STORE_AUTHORIZATION_ERROR"
)

// Rate limiter configuration
type RateLimiterConfig struct {
	Limit  int
	Window time.Duration
}
