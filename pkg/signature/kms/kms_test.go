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

// Package kms implements the interface to access various ksm services
package kms

import (
	"context"
	"crypto"
	"errors"
	"os/exec"
	"testing"
)

// TestGetCLIPluginLoadAttempt ensures that there is an attempt to load the PluginClient.
// Other KMS providers can't really be tested here because we would have to import them, causing circular imports.
func TestGetCLIPluginLoadAttempt(t *testing.T) {
	t.Parallel()

	testHashFunc := crypto.SHA256
	testCtx := context.Background()
	testKey := "gundam://00"

	// exec.ErrNotFound is returned by cliplugin.LoadSignerVerifier().
	if _, err := Get(testCtx, testKey, testHashFunc); !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("wanted exec.ErrNotFound, got: %v", err)
	}
}
