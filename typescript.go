package livego

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
)

func (h *Handler) GenerateTSTypes() string {
	var buf bytes.Buffer
	buf.WriteString("export type ComponentTypes = {\n")

	for name, factory := range h.components { // Assuming 'registrations' is the map of name to factory func
		comp := factory(context.Background()) // Create an instance to reflect on
		typ := reflect.TypeOf(comp).Elem()    // Assuming pointer receiver, deref to struct

		// State: from JSON-tagged fields
		buf.WriteString(fmt.Sprintf("  '%s': {\n    state: {\n", name))
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			jsonTag := field.Tag.Get("json")
			if jsonTag == "" || jsonTag == "-" || field.Name == "BaseComponent" { // Skip base or untagged
				continue
			}
			tsType := goToTSType(field.Type)
			buf.WriteString(fmt.Sprintf("      %s: %s;\n", jsonTag, tsType))
		}
		buf.WriteString("    };\n")

		// Actions: public methods as mapped types with args
		buf.WriteString("    actions: {\n")
		hasActions := false
		for i := 0; i < typ.NumMethod(); i++ {
			meth := typ.Method(i)
			if !isActionMethod(meth) { // Filter lifecycle or non-actions
				continue
			}
			hasActions = true
			buf.WriteString(fmt.Sprintf("      '%s': { args: [", meth.Name))
			for j := 1; j < meth.Type.NumIn(); j++ { // Skip receiver
				argType := goToTSType(meth.Type.In(j))
				buf.WriteString(argType)
				if j < meth.Type.NumIn()-1 {
					buf.WriteString(", ")
				}
			}
			buf.WriteString("] };\n")
		}
		if !hasActions {
			buf.WriteString("      [key: string]: never;\n") // Or just {}
		}
		buf.WriteString("    };\n")

		buf.WriteString("  };\n")
	}

	buf.WriteString("};\n")
	return buf.String()
}

func goToTSType(t reflect.Type) string {
	switch t.Kind() {
	// Numeric types -> number
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return "number"
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "number"
	case reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Complex64, reflect.Complex128:
		return "number" // or "Complex" if you have a custom type

	// String types
	case reflect.String:
		return "string"

	// Boolean
	case reflect.Bool:
		return "boolean"

	// Arrays and Slices -> T[]
	case reflect.Array, reflect.Slice:
		elemType := goToTSType(t.Elem())
		// Special case: []byte -> string (common convention)
		if t.Elem().Kind() == reflect.Uint8 {
			return "string"
		}
		return elemType + "[]"

	// Maps -> Record<K, V> or { [key: K]: V }
	case reflect.Map:
		keyType := goToTSType(t.Key())
		valueType := goToTSType(t.Elem())
		return fmt.Sprintf("Record<%s, %s>", keyType, valueType)

	// Structs -> interface (needs recursive handling)
	case reflect.Struct:
		// Special cases for common types
		if t.PkgPath() == "time" && t.Name() == "Time" {
			return "string" // ISO 8601 format
		}
		return "interface" // placeholder - needs struct field iteration

	// Pointers -> T | null
	case reflect.Ptr:
		elemType := goToTSType(t.Elem())
		return elemType + " | null"

	// Interface -> any or unknown
	case reflect.Interface:
		return "any" // or "unknown" for stricter typing

	// Functions -> function signature
	case reflect.Func:
		return "Function" // or build proper signature

	// Channels -> not directly mappable
	case reflect.Chan:
		return "any" // channels don't have TS equivalent

	// Unsafe pointer
	case reflect.UnsafePointer:
		return "any"

	// Invalid or unhandled
	case reflect.Invalid:
		return "never"

	default:
		return "any"
	}
}

func isActionMethod(m reflect.Method) bool {
	if m.Type.NumIn() != 1 { // Only receiver, no args
		return false
	}
	if m.Type.NumOut() > 0 { // No returns (or check for error?)
		return false
	}
	// Exclude lifecycle
	excluded := []string{"Mount", "AuthorizeMount", "AuthorizeUpdate"}
	for _, ex := range excluded {
		if m.Name == ex {
			return false
		}
	}
	return true // Public by default since NumMethod() only publics
}
