package livego

import (
	"fmt"
	"reflect"
	"regexp"
	"unicode"
)

// Validation functions for input sanitization and security

// validateComponentName validates component names to prevent injection attacks
func validateComponentName(name string) error {
	if name == "" {
		return fmt.Errorf("component name cannot be empty")
	}

	if len(name) > 100 {
		return fmt.Errorf("component name too long (max 100 characters)")
	}

	// Allow alphanumeric, underscore, and dash
	if matched, _ := regexp.MatchString("^[a-zA-Z0-9_-]+$", name); !matched {
		return fmt.Errorf("component name contains invalid characters")
	}

	return nil
}

// validateMethodName validates method names to ensure they are safe to call
func validateMethodName(name string) error {
	if name == "" {
		return fmt.Errorf("method name cannot be empty")
	}

	if len(name) > 100 {
		return fmt.Errorf("method name too long (max 100 characters)")
	}

	// Method name must start with uppercase (Go exported method)
	if !unicode.IsUpper(rune(name[0])) {
		return fmt.Errorf("method name must be exported (start with uppercase)")
	}

	// Allow alphanumeric and underscore only
	if matched, _ := regexp.MatchString("^[a-zA-Z][a-zA-Z0-9_]*$", name); !matched {
		return fmt.Errorf("method name contains invalid characters")
	}

	// Blacklist dangerous method names
	dangerousMethods := []string{
		"Finalize", "SetFinalizer", "String", "GoString",
		"Error", "Write", "Read", "Close", "Seek",
	}

	for _, dangerous := range dangerousMethods {
		if name == dangerous {
			return fmt.Errorf("method name '%s' is not allowed", name)
		}
	}

	return nil
}

// validateFieldName validates field names for syncInput operations
func validateFieldName(name string) error {
	if name == "" {
		return fmt.Errorf("field name cannot be empty")
	}

	if len(name) > 100 {
		return fmt.Errorf("field name too long (max 100 characters)")
	}

	// Field name must start with uppercase (Go exported field)
	if !unicode.IsUpper(rune(name[0])) {
		return fmt.Errorf("field name must be exported (start with uppercase)")
	}

	// Allow alphanumeric and underscore only
	if matched, _ := regexp.MatchString("^[a-zA-Z][a-zA-Z0-9_]*$", name); !matched {
		return fmt.Errorf("field name contains invalid characters")
	}

	return nil
}

// validateStoreKey validates store keys to prevent injection attacks
func validateStoreKey(key string) error {
	if key == "" {
		return fmt.Errorf("store key cannot be empty")
	}

	if len(key) > 100 {
		return fmt.Errorf("store key too long (max 100 characters)")
	}

	// Allow alphanumeric, underscore, dash, and dot
	if matched, _ := regexp.MatchString("^[a-zA-Z0-9_.-]+$", key); !matched {
		return fmt.Errorf("store key contains invalid characters")
	}

	return nil
}

// isMethodCallable checks if a method is safe to call via reflection
func isMethodCallable(method reflect.Method) bool {
	// Method must be exported (public)
	if !method.IsExported() {
		return false
	}

	// Method name must pass validation
	if err := validateMethodName(method.Name); err != nil {
		return false
	}

	return true
}
