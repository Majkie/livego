package livego

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
)

// BaseComponent provides common functionality for components
type BaseComponent struct {
	ID string `json:"-"`
}

func (b *BaseComponent) Mount() error {
	return nil
}

func (b *BaseComponent) GetID() string {
	return b.ID
}

func (b *BaseComponent) SetID(id string) {
	b.ID = id
}

func (b *BaseComponent) Hydrate(state map[string]interface{}) error {
	// Use reflection to set fields
	v := reflect.ValueOf(b).Elem()
	for key, value := range state {
		field := v.FieldByName(key)
		if field.IsValid() && field.CanSet() {
			field.Set(reflect.ValueOf(value))
		}
	}
	return nil
}

func (b *BaseComponent) Dehydrate() map[string]interface{} {
	result := make(map[string]interface{})
	v := reflect.ValueOf(b).Elem()
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		if field.Tag.Get("json") != "-" {
			result[field.Name] = v.Field(i).Interface()
		}
	}

	return result
}

// Component utility functions

// DehydrateComponent converts a component to a map suitable for JSON serialization
func DehydrateComponent(c Component) map[string]interface{} {
	if c == nil {
		return map[string]interface{}{}
	}

	// Marshal the concrete component to JSON (respects json tags)
	b, err := json.Marshal(c)
	if err != nil {
		// fallback to empty state on error
		return map[string]interface{}{}
	}

	// Unmarshal into a map[string]interface{} so the handler gets JSON-like state
	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		return map[string]interface{}{}
	}

	return out
}

// HydrateComponent loads state data into a component
func HydrateComponent(c Component, state map[string]interface{}) error {
	if c == nil {
		return fmt.Errorf("component is nil")
	}

	// Marshal the incoming state map to JSON
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}

	// Unmarshal JSON into the concrete component (c must be pointer to struct)
	if err := json.Unmarshal(b, c); err != nil {
		return err
	}

	return nil
}

// generateComponentID creates a cryptographically secure component ID
func generateComponentID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		panic("failed to generate random ID")
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

// convertParam converts a parameter value to the target type using JSON marshaling/unmarshaling
func convertParam(value interface{}, targetType reflect.Type) (reflect.Value, error) {
	jsonBytes, _ := json.Marshal(value)
	targetVal := reflect.New(targetType)
	if err := json.Unmarshal(jsonBytes, targetVal.Interface()); err != nil {
		return reflect.Value{}, err
	}
	return targetVal.Elem(), nil
}
