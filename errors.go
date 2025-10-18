package livego

import (
	"encoding/json"
	"net/http"
)

// Error handling and JSON response functions

// writeJSONError writes a structured JSON error response
func writeJSONError(w http.ResponseWriter, errorType string, message string, statusCode int, details map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	errorResponse := ErrorResponse{
		Error:   errorType,
		Message: message,
		Code:    statusCode,
		Details: details,
	}

	json.NewEncoder(w).Encode(errorResponse)
}

// Common error response helpers

func writeBadRequestError(w http.ResponseWriter, message string, details map[string]interface{}) {
	writeJSONError(w, ErrorBadRequest, message, http.StatusBadRequest, details)
}

func writeUnauthorizedError(w http.ResponseWriter, message string, details map[string]interface{}) {
	writeJSONError(w, ErrorUnauthorized, message, http.StatusUnauthorized, details)
}

func writeForbiddenError(w http.ResponseWriter, message string, details map[string]interface{}) {
	writeJSONError(w, ErrorForbidden, message, http.StatusForbidden, details)
}

func writeNotFoundError(w http.ResponseWriter, message string, details map[string]interface{}) {
	writeJSONError(w, ErrorNotFound, message, http.StatusNotFound, details)
}

func writeMethodNotAllowedError(w http.ResponseWriter, message string) {
	writeJSONError(w, ErrorMethodNotAllowed, message, http.StatusMethodNotAllowed, nil)
}

func writeInternalServerError(w http.ResponseWriter, message string, details map[string]interface{}) {
	writeJSONError(w, ErrorInternalServer, message, http.StatusInternalServerError, details)
}

func writeValidationError(w http.ResponseWriter, message string, details map[string]interface{}) {
	writeJSONError(w, ErrorValidation, message, http.StatusBadRequest, details)
}

func writeComponentError(w http.ResponseWriter, errorType string, message string, statusCode int, details map[string]interface{}) {
	writeJSONError(w, errorType, message, statusCode, details)
}

func writeRateLimitError(w http.ResponseWriter, message string, details map[string]interface{}) {
	writeJSONError(w, ErrorRateLimit, message, http.StatusTooManyRequests, details)
}
