package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectedErr error
	}{
		{
			name:        "Valid API key",
			headers:     http.Header{"Authorization": []string{"ApiKey my-api-key"}},
			expectedKey: "my-api-key",
			expectedErr: nil,
		},
		{
			name:        "No Authorization header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "Empty Authorization header",
			headers:     http.Header{"Authorization": []string{""}},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "Malformed header - no ApiKey prefix",
			headers:     http.Header{"Authorization": []string{"Bearer token"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "Malformed header - missing key",
			headers:     http.Header{"Authorization": []string{"ApiKey "}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "Malformed header - single value",
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)
			if key != tt.expectedKey {
				t.Errorf("GetAPIKey() key = %v, want %v", key, tt.expectedKey)
			}
			if !errors.Is(err, tt.expectedErr) && err != nil && err.Error() != tt.expectedErr.Error() {
				t.Errorf("GetAPIKey() error = %v, want %v", err, tt.expectedErr)
			}
		})
	}
}
