package livego

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"time"
)

// Handler with enhanced security
type Handler struct {
	secret           string
	components       map[string]ComponentFactory
	stores           map[string]StoreFactory
	checksumLifetime time.Duration // How long checksums are valid
}

// NewHandler creates a new LiveGo handler
func NewHandler(secret string) *Handler {
	return &Handler{
		secret:           secret,
		components:       make(map[string]ComponentFactory),
		stores:           make(map[string]StoreFactory),
		checksumLifetime: 2 * time.Hour, // Checksums expire after 2 hours
	}
}

// SetChecksumLifetime sets the checksum expiration duration
func (h *Handler) SetChecksumLifetime(d time.Duration) {
	h.checksumLifetime = d
}

// Register registers a component factory
func (h *Handler) Register(name string, factory ComponentFactory) {
	h.components[name] = factory
}

// RegisterStore registers a store factory
func (h *Handler) RegisterStore(key string, factory StoreFactory) {
	h.stores[key] = factory
}

func (h *Handler) InitializeStreaming() *StreamManager {
	return NewStreamManager(h.secret)
}

// createComponent instantiates a component by name
func (h *Handler) createComponent(ctx context.Context, name string) Component {
	factory, exists := h.components[name]
	if !exists {
		return nil
	}
	return factory(ctx)
}

// HandleMount mounts a single component
func (h *Handler) HandleMount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowedError(w, "Method not allowed")
		return
	}

	var req MountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequestError(w, "Invalid request body", map[string]interface{}{
			"parse_error": err.Error(),
		})
		return
	}

	// Validate component name
	if err := validateComponentName(req.Component); err != nil {
		writeValidationError(w, "Invalid component name: "+err.Error(), map[string]interface{}{
			"component_name":   req.Component,
			"validation_error": err.Error(),
		})
		return
	}

	// Create component instance
	component := h.createComponent(r.Context(), req.Component)
	if component == nil {
		writeComponentError(w, ErrorComponentNotFound, "Component not found: "+req.Component, http.StatusNotFound, map[string]interface{}{
			"component_name": req.Component,
		})
		return
	}

	if authComponent, ok := component.(MountAuthorizer); ok {
		if err := authComponent.AuthorizeMount(r.Context()); err != nil {
			writeUnauthorizedError(w, "Component mount not authorized: "+err.Error(), map[string]interface{}{
				"component_name": req.Component,
				"auth_error":     err.Error(),
			})
			return
		}
	}

	// Generate unique component ID
	componentID := generateComponentID()
	component.SetID(componentID)

	if len(req.Props) > 0 {
		if err := HydrateComponent(component, req.Props); err != nil {
			writeComponentError(w, ErrorComponentHydration, "Failed to hydrate props: "+err.Error(), http.StatusBadRequest, map[string]interface{}{
				"component_name":  req.Component,
				"component_id":    componentID,
				"hydration_error": err.Error(),
			})
			return
		}
	}

	if err := component.Mount(); err != nil {
		writeComponentError(w, ErrorComponentMount, "Mount failed: "+err.Error(), http.StatusInternalServerError, map[string]interface{}{
			"component_name": req.Component,
			"component_id":   componentID,
			"mount_error":    err.Error(),
		})
		return
	}

	// Create memo
	memo := ComponentMemo{
		ID:       componentID,
		Name:     req.Component,
		Path:     r.URL.Path,
		Method:   r.Method,
		Children: []string{},
		Data:     req.Props, // Store props in memo
	}

	// Dehydrate state
	state := DehydrateComponent(component)

	// Generate checksum
	checksum := generateChecksum(h.secret, state, memo)

	// Create snapshot
	snapshot := ComponentSnapshot{
		State:    state,
		Memo:     memo,
		Checksum: checksum,
	}
	// Return response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(MountResponse{
		Snapshot: snapshot,
	})
}

// HandleUpdate handles component updates
func (h *Handler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	var req UpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequestError(w, "Invalid request", map[string]interface{}{
			"parse_error": err.Error(),
		})
		return
	}

	// 2. Verify checksum
	if !verifyChecksum(h.secret, req.Snapshot) { // <-- uses HMAC check
		writeComponentError(w, ErrorChecksumMismatch, "Checksum mismatch - potential tampering", http.StatusForbidden, map[string]interface{}{
			"component_id":   req.Snapshot.Memo.ID,
			"component_name": req.Snapshot.Memo.Name,
			"security_error": "Component tampering detected",
		})
		return
	}

	// 3. Create component & hydrate state
	component := h.createComponent(r.Context(), req.Snapshot.Memo.Name)
	if component == nil {
		writeComponentError(w, ErrorComponentNotFound, "Component not found", http.StatusNotFound, map[string]interface{}{
			"component_id":   req.Snapshot.Memo.ID,
			"component_name": req.Snapshot.Memo.Name,
		})
		return
	}
	component.SetID(req.Snapshot.Memo.ID)

	if err := HydrateComponent(component, req.Snapshot.State); err != nil {
		writeComponentError(w, ErrorComponentHydration, "Hydration failed", http.StatusInternalServerError, map[string]interface{}{
			"component_id":    req.Snapshot.Memo.ID,
			"component_name":  req.Snapshot.Memo.Name,
			"hydration_error": err.Error(),
		})
		return
	}

	// 4. Execute updates
	effects := &Effects{
		Dirty:      []string{},
		Dispatches: []map[string]interface{}{},
	}

	for _, update := range req.Updates {
		if authComponent, ok := component.(UpdateAuthorizer); ok {
			if err := authComponent.AuthorizeUpdate(r.Context(), update.Type, update.Payload); err != nil {
				writeUnauthorizedError(w, "Unauthorized: "+err.Error(), map[string]interface{}{
					"component_id":   req.Snapshot.Memo.ID,
					"component_name": req.Snapshot.Memo.Name,
					"update_type":    update.Type,
					"auth_error":     err.Error(),
				})
				return
			}
		}

		if err := h.executeUpdate(component, update, effects); err != nil {
			writeComponentError(w, ErrorComponentUpdate, err.Error(), http.StatusBadRequest, map[string]interface{}{
				"component_id":    req.Snapshot.Memo.ID,
				"component_name":  req.Snapshot.Memo.Name,
				"update_type":     update.Type,
				"execution_error": err.Error(),
			})
			return
		}
	}

	// 5. Create new snapshot (fresh state + new checksum)
	newSnapshot := h.createSnapshot(component, req.Snapshot.Memo)

	// 6. Return response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(UpdateResponse{
		Snapshot: newSnapshot,
		Effects:  *effects,
	})
}

// HandlePageMount mounts multiple components at once (STATELESS)
func (h *Handler) HandlePageMount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowedError(w, "Method not allowed")
		return
	}

	var req PageMountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequestError(w, "Invalid request body", map[string]interface{}{
			"parse_error": err.Error(),
		})
		return
	}

	// Build component hierarchy
	hierarchy := make(map[string]*string)
	for _, compReq := range req.Components {
		hierarchy[compReq.ID] = compReq.ParentID
	}

	snapshots := make(map[string]ComponentSnapshot)
	components := make(map[string]Component)
	now := time.Now().Unix()

	// First pass: Create and mount all components
	for _, compReq := range req.Components {
		component := h.createComponent(r.Context(), compReq.Component)
		if component == nil {
			writeComponentError(w, ErrorComponentNotFound, "Component not found: "+compReq.Component, http.StatusNotFound, map[string]interface{}{
				"component_name": compReq.Component,
				"component_id":   compReq.ID,
			})
			return
		}

		// Authorization
		if authComponent, ok := component.(MountAuthorizer); ok {
			if err := authComponent.AuthorizeMount(r.Context()); err != nil {
				writeUnauthorizedError(w, "Component mount not authorized: "+err.Error(), map[string]interface{}{
					"component_name": compReq.Component,
					"component_id":   compReq.ID,
				})
				return
			}
		}

		component.SetID(compReq.ID)

		// Hydrate props
		if len(compReq.Props) > 0 {
			if err := HydrateComponent(component, compReq.Props); err != nil {
				writeComponentError(w, ErrorComponentHydration, "Failed to hydrate props: "+err.Error(), http.StatusBadRequest, map[string]interface{}{
					"component_name":  compReq.Component,
					"component_id":    compReq.ID,
					"hydration_error": err.Error(),
				})
				return
			}
		}

		// Mount
		if err := component.Mount(); err != nil {
			writeComponentError(w, ErrorComponentMount, "Mount failed: "+err.Error(), http.StatusInternalServerError, map[string]interface{}{
				"component_name": compReq.Component,
				"component_id":   compReq.ID,
				"mount_error":    err.Error(),
			})
			return
		}

		components[compReq.ID] = component
	}

	// Second pass: Inject parent data into children
	for id, component := range components {
		if parentID := hierarchy[id]; parentID != nil {
			if parent, ok := components[*parentID]; ok {
				if parentComp, ok := parent.(PageComponent); ok {
					if childComp, ok := component.(ChildComponent); ok {
						childComp.OnParentDataChange(parentComp.ProvideData())
					}
				}
			}
		}
	}

	// Third pass: Create snapshots with relationships
	for _, compReq := range req.Components {
		component := components[compReq.ID]

		// Build relationship data
		relationship := ComponentRelationship{
			ParentID: compReq.ParentID,
			Children: []string{},
		}

		// Find children
		for childID, parentID := range hierarchy {
			if parentID != nil && *parentID == compReq.ID {
				relationship.Children = append(relationship.Children, childID)
			}
		}

		memo := EnhancedComponentMemo{
			ComponentMemo: ComponentMemo{
				ID:       compReq.ID,
				Name:     compReq.Component,
				Path:     r.URL.Path,
				Method:   r.Method,
				Children: relationship.Children,
				Data:     compReq.Props,
			},
			Relationship: relationship,
			MountedAt:    now,
		}

		state := DehydrateComponent(component)
		checksum := generateTimedChecksum(h.secret, state, memo)

		snapshots[compReq.ID] = ComponentSnapshot{
			State:    state,
			Memo:     memo.ComponentMemo,
			Checksum: checksum,
		}
	}

	// Sign global state
	globalState := signGlobalState(h.secret, req.Global)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(PageMountResponse{
		Components: snapshots,
		Global:     globalState,
	})
}

// HandlePageUpdate updates one or more components (STATELESS)
func (h *Handler) HandlePageUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowedError(w, "Method not allowed")
		return
	}

	var req PageUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequestError(w, "Invalid request", map[string]interface{}{
			"parse_error": err.Error(),
		})
		return
	}

	// CRITICAL: Verify global state signature
	if !verifyGlobalState(h.secret, req.Global) {
		writeForbiddenError(w, "Global state signature invalid", map[string]interface{}{
			"security_error": "Global state tampering detected",
		})
		return
	}

	// CRITICAL: Verify all component checksums and timestamps
	for id, snapshot := range req.Components {
		if !verifyTimedChecksum(h.secret, snapshot, h.checksumLifetime) {
			writeComponentError(w, ErrorChecksumMismatch, fmt.Sprintf("Component %s checksum invalid or expired", id), http.StatusForbidden, map[string]interface{}{
				"component_id":   id,
				"component_name": snapshot.Memo.Name,
				"security_error": "Component tampering detected or checksum expired",
			})
			return
		}
	}

	// Reconstruct component hierarchy from memos
	hierarchy := make(map[string]*string)
	for id, snapshot := range req.Components {
		// Extract parent from memo data if available
		if parentID, ok := snapshot.Memo.Data["parentId"].(string); ok && parentID != "" {
			hierarchy[id] = &parentID
		} else {
			hierarchy[id] = nil
		}
	}

	// Recreate all components with current state
	components := make(map[string]Component)
	for id, snapshot := range req.Components {
		component := h.createComponent(r.Context(), snapshot.Memo.Name)
		if component == nil {
			writeComponentError(w, ErrorComponentNotFound, "Component not found: "+snapshot.Memo.Name, http.StatusNotFound, map[string]interface{}{
				"component_name": snapshot.Memo.Name,
				"component_id":   id,
			})
			return
		}

		component.SetID(id)

		if err := HydrateComponent(component, snapshot.State); err != nil {
			writeComponentError(w, ErrorComponentHydration, "Hydration failed", http.StatusInternalServerError, map[string]interface{}{
				"component_name":  snapshot.Memo.Name,
				"component_id":    id,
				"hydration_error": err.Error(),
			})
			return
		}

		components[id] = component
	}

	// Track which components need updates
	dirtyComponents := make(map[string]bool)
	effects := &Effects{
		Dirty:      []string{},
		Dispatches: []map[string]interface{}{},
	}

	// Execute updates
	for _, updateReq := range req.Updates {
		component, ok := components[updateReq.ID]
		if !ok {
			writeComponentError(w, ErrorComponentNotFound, "Component not found: "+updateReq.ID, http.StatusNotFound, map[string]interface{}{
				"component_id": updateReq.ID,
			})
			return
		}

		for _, update := range updateReq.Updates {
			// Authorization check
			if authComponent, ok := component.(UpdateAuthorizer); ok {
				if err := authComponent.AuthorizeUpdate(r.Context(), update.Type, update.Payload); err != nil {
					writeUnauthorizedError(w, "Unauthorized: "+err.Error(), map[string]interface{}{
						"component_id": updateReq.ID,
						"update_type":  update.Type,
						"auth_error":   err.Error(),
					})
					return
				}
			}

			if err := h.executeUpdate(component, update, effects); err != nil {
				writeComponentError(w, ErrorComponentUpdate, err.Error(), http.StatusBadRequest, map[string]interface{}{
					"component_id":    updateReq.ID,
					"update_type":     update.Type,
					"execution_error": err.Error(),
				})
				return
			}
		}

		dirtyComponents[updateReq.ID] = true

		// Mark children as dirty if this is a parent
		if parentComp, ok := component.(PageComponent); ok {
			parentData := parentComp.ProvideData()

			// Find and update children
			for childID, parentID := range hierarchy {
				if parentID != nil && *parentID == updateReq.ID {
					if child, ok := components[childID]; ok {
						if childComp, ok := child.(ChildComponent); ok {
							childComp.OnParentDataChange(parentData)
							dirtyComponents[childID] = true
						}
					}
				}
			}
		}

		// Mark parent as dirty if this is a child
		if parentID := hierarchy[updateReq.ID]; parentID != nil {
			dirtyComponents[*parentID] = true
		}
	}

	// Build response with only dirty components
	responseSnapshots := make(map[string]ComponentSnapshot)
	now := time.Now().Unix()

	for id := range dirtyComponents {
		component := components[id]
		originalSnapshot := req.Components[id]

		// Rebuild relationship data
		relationship := ComponentRelationship{
			ParentID: hierarchy[id],
			Children: []string{},
		}

		for childID, parentID := range hierarchy {
			if parentID != nil && *parentID == id {
				relationship.Children = append(relationship.Children, childID)
			}
		}

		memo := EnhancedComponentMemo{
			ComponentMemo: ComponentMemo{
				ID:       id,
				Name:     originalSnapshot.Memo.Name,
				Path:     originalSnapshot.Memo.Path,
				Method:   originalSnapshot.Memo.Method,
				Children: relationship.Children,
				Data:     originalSnapshot.Memo.Data,
			},
			Relationship: relationship,
			MountedAt:    now,
		}

		state := DehydrateComponent(component)
		checksum := generateTimedChecksum(h.secret, state, memo)

		responseSnapshots[id] = ComponentSnapshot{
			State:    state,
			Memo:     memo.ComponentMemo,
			Checksum: checksum,
		}
	}

	// Re-sign global state
	globalState := signGlobalState(h.secret, req.Global.Data)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(PageUpdateResponse{
		Components: responseSnapshots,
		Global:     globalState,
	})
}

func (h *Handler) HandleStreamedUpdate(streamManager *StreamManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req UpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeBadRequestError(w, "Invalid request", map[string]interface{}{
				"parse_error": err.Error(),
			})
			return
		}

		// Verify checksum
		if !verifyChecksum(h.secret, req.Snapshot) {
			writeComponentError(w, ErrorChecksumMismatch, "Checksum mismatch", http.StatusForbidden, nil)
			return
		}

		// Create component & hydrate
		component := h.createComponent(r.Context(), req.Snapshot.Memo.Name)
		if component == nil {
			writeComponentError(w, ErrorComponentNotFound, "Component not found", http.StatusNotFound, nil)
			return
		}
		component.SetID(req.Snapshot.Memo.ID)

		if err := HydrateComponent(component, req.Snapshot.State); err != nil {
			writeComponentError(w, ErrorComponentHydration, "Hydration failed", http.StatusInternalServerError, nil)
			return
		}

		// Execute updates
		effects := &Effects{
			Dirty:      []string{},
			Dispatches: []map[string]interface{}{},
		}

		for _, update := range req.Updates {
			if authComponent, ok := component.(UpdateAuthorizer); ok {
				if err := authComponent.AuthorizeUpdate(r.Context(), update.Type, update.Payload); err != nil {
					writeUnauthorizedError(w, "Unauthorized: "+err.Error(), nil)
					return
				}
			}

			if err := h.executeUpdate(component, update, effects); err != nil {
				writeComponentError(w, ErrorComponentUpdate, err.Error(), http.StatusBadRequest, nil)
				return
			}
		}

		// Check if component supports streaming
		if streamComp, ok := component.(StreamComponent); ok {
			streamCtx := &StreamContext{
				componentID: component.GetID(),
				manager:     streamManager,
				ctx:         r.Context(),
			}

			// Trigger streaming (async)
			go func() {
				if err := streamComp.OnStream(streamCtx); err != nil {
					// Log error but don't fail the request
					fmt.Printf("Stream error: %v\n", err)
				}
			}()
		}

		// Return normal update response with stream signature
		newSnapshot := h.createSnapshot(component, req.Snapshot.Memo)
		streamSignature := streamManager.GenerateStreamSignature(component.GetID())

		response := struct {
			Snapshot        ComponentSnapshot `json:"snapshot"`
			Effects         Effects           `json:"effects"`
			StreamSignature string            `json:"stream_signature,omitempty"`
		}{
			Snapshot:        newSnapshot,
			Effects:         *effects,
			StreamSignature: streamSignature,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// Helper methods

// createSnapshot creates a new component snapshot
func (h *Handler) createSnapshot(component Component, memo ComponentMemo) ComponentSnapshot {
	state := DehydrateComponent(component)
	memo.ID = component.GetID()

	checksum := generateChecksum(h.secret, state, memo)

	return ComponentSnapshot{
		State:    state,
		Memo:     memo,
		Checksum: checksum,
	}
}

// executeUpdate executes a single update on the component
func (h *Handler) executeUpdate(component Component, update Update, effects *Effects) error {
	switch update.Type {
	case "callMethod":
		method := update.Payload["method"].(string)
		params := update.Payload["params"].([]interface{})
		return h.callMethod(component, method, params, effects)
	case "syncInput":
		field := update.Payload["field"].(string)
		value := update.Payload["value"]
		return h.syncInput(component, field, value, effects)
	default:
		return fmt.Errorf("unknown update type: %s", update.Type)
	}
}

// callMethod calls a method on the component using reflection with security checks
func (h *Handler) callMethod(component Component, method string, params []interface{}, effects *Effects) error {
	// Validate method name first
	if err := validateMethodName(method); err != nil {
		return fmt.Errorf("invalid method name: %w", err)
	}

	v := reflect.ValueOf(component)
	componentType := v.Type()

	// Find the method and ensure it's callable (single lookup optimization)
	targetMethod, found := componentType.MethodByName(method)
	if !found {
		return fmt.Errorf("method not found: %s", method)
	}

	if !isMethodCallable(targetMethod) {
		return fmt.Errorf("method '%s' is not callable (must be exported and safe)", method)
	}

	// Get the method value using the already found method
	methodValue := v.Method(targetMethod.Index)
	if !methodValue.IsValid() {
		return fmt.Errorf("method not valid: %s", method)
	}

	methodType := targetMethod.Type
	// methodType.NumIn() includes the receiver, but we don't pass it in params
	// so we need to subtract 1 from the expected count
	expectedParams := methodType.NumIn() - 1
	if len(params) != expectedParams {
		return fmt.Errorf("parameter count mismatch: expected %d, got %d", expectedParams, len(params))
	}

	// Convert params to reflect.Value with type checking (pre-allocated for performance)
	in := make([]reflect.Value, len(params))
	for i, param := range params {
		// methodType.In(0) is the receiver, so we need to skip it and use i+1
		expectedType := methodType.In(i + 1)
		converted, err := convertParam(param, expectedType)
		if err != nil {
			return fmt.Errorf("param %d conversion failed: %w", i, err)
		}
		in[i] = converted
	}

	// Call method safely
	results := methodValue.Call(in)

	// Handle method errors if the method returns an error
	if len(results) > 0 {
		lastResult := results[len(results)-1]
		if lastResult.Type().Implements(reflect.TypeOf((*error)(nil)).Elem()) {
			if !lastResult.IsNil() {
				return lastResult.Interface().(error)
			}
		}
	}

	// Track that this component is dirty
	effects.Dirty = append(effects.Dirty, component.GetID())

	return nil
}

// syncInput updates a component property with security checks
func (h *Handler) syncInput(component Component, field string, value interface{}, effects *Effects) error {
	// Validate field name first
	if err := validateFieldName(field); err != nil {
		return fmt.Errorf("invalid field name: %w", err)
	}

	v := reflect.ValueOf(component).Elem()
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("component is not a struct")
	}

	structType := v.Type()

	// Find the field and ensure it's accessible (optimized lookup)
	targetField, found := structType.FieldByName(field)
	if !found {
		return fmt.Errorf("field not found: %s", field)
	}

	// Field must be exported (public)
	if !targetField.IsExported() {
		return fmt.Errorf("field '%s' is not exported", field)
	}

	f := v.FieldByName(field)
	if !f.IsValid() {
		return fmt.Errorf("field not valid: %s", field)
	}

	if !f.CanSet() {
		return fmt.Errorf("field not settable: %s", field)
	}

	// Convert and validate the value type
	valueReflect := reflect.ValueOf(value)
	if !valueReflect.Type().AssignableTo(targetField.Type) {
		// Try to convert the value
		if valueReflect.Type().ConvertibleTo(targetField.Type) {
			valueReflect = valueReflect.Convert(targetField.Type)
		} else {
			return fmt.Errorf("value type %v is not assignable to field type %v",
				valueReflect.Type(), targetField.Type)
		}
	}

	f.Set(valueReflect)
	effects.Dirty = append(effects.Dirty, component.GetID())

	return nil
}
