//
// Copyright 2025 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cliplugin

import (
	"errors"
	"testing"
)

// TestGetPluginExecutableAndKeyResourceID ensures that the plugin name is parsed
// and that names which would be resolved outside of PATH are rejected.
func TestGetPluginExecutableAndKeyResourceID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		inputKeyResourceID string
		wantExecutable     string
		wantKeyResourceID  string
		wantErr            error
	}{
		{
			name:               "valid",
			inputKeyResourceID: "my-hsm://my-key-id",
			wantExecutable:     "sigstore-kms-my-hsm",
			wantKeyResourceID:  "my-key-id",
		},
		{
			name:               "key ref with path",
			inputKeyResourceID: "my-hsm://path/to/key",
			wantExecutable:     "sigstore-kms-my-hsm",
			wantKeyResourceID:  "path/to/key",
		},
		{
			name:               "missing separator",
			inputKeyResourceID: "my-hsm",
			wantErr:            ErrorInputKeyResourceID,
		},
		{
			name:               "slash in plugin name",
			inputKeyResourceID: "evil/x://my-key-id",
			wantErr:            ErrorInputKeyResourceID,
		},
		{
			name:               "traversal in plugin name",
			inputKeyResourceID: "x/../../tmp/evil://my-key-id",
			wantErr:            ErrorInputKeyResourceID,
		},
		{
			name:               "backslash in plugin name",
			inputKeyResourceID: `evil\x://my-key-id`,
			wantErr:            ErrorInputKeyResourceID,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			executable, keyResourceID, err := getPluginExecutableAndKeyResourceID(tc.inputKeyResourceID)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("unexpected error: got %v, want %v", err, tc.wantErr)
			}
			if executable != tc.wantExecutable {
				t.Errorf("unexpected executable: got %q, want %q", executable, tc.wantExecutable)
			}
			if keyResourceID != tc.wantKeyResourceID {
				t.Errorf("unexpected key resource id: got %q, want %q", keyResourceID, tc.wantKeyResourceID)
			}
		})
	}
}
