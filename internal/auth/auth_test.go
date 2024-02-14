package auth

import (
	"net/http"
	"testing"
)

// TestGetAPIKeyMissingHeader tests the scenario where the Authorization header is missing.
func TestGetAPIKeyMissingHeader(t *testing.T) {
	headers := make(http.Header)
	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("Expected error '%v', got '%v'", ErrNoAuthHeaderIncluded, err)
	}
}

// TestGetAPIKeyMalformedHeader tests the scenario where the Authorization header is malformed.
func TestGetAPIKeyMalformedHeader(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{"EmptyValue", ""},
		{"InvalidScheme", "Bearer token"},
		{"NoToken", "ApiKey"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := make(http.Header)
			headers.Set("Authorization", tc.header)
			_, err := GetAPIKey(headers)
			if err == nil || err == ErrNoAuthHeaderIncluded {
				t.Errorf("Expected a malformed header error, got '%v'", err)
			}
		})
	}
}

// TestGetAPIKeySuccess tests the scenario where the Authorization header is correct.
func TestGetAPIKeySuccess(t *testing.T) {
	expectedAPIKey := "12345"
	headers := make(http.Header)
	headers.Set("Authorization", "ApiKey "+expectedAPIKey)
	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Errorf("Did not expect an error, got '%v'", err)
	}
	if apiKey != expectedAPIKey {
		t.Errorf("Expected API key '%s', got '%s'", expectedAPIKey, apiKey)
	}
}

