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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sigstore/sigstore/pkg/signature"
)

// TestGet ensures that there is are load attempts on registered providers, including the CLIPlugin,
// and it returns the correct errors.
func TestGet(t *testing.T) {
	t.Parallel()

	testHashFunc := crypto.SHA256
	testCtx := context.Background()

	t.Run("cliplugin", func(t *testing.T) {
		t.Parallel()

		testKey := "gundam://00"
		var providerNotFoundError *ProviderNotFoundError

		// we only check for errors because we can't assume that there exists on the system
		// a program prefixed with "sigstore-kms-".
		_, err := Get(testCtx, testKey, testHashFunc)
		if !errors.As(err, &providerNotFoundError) {
			t.Errorf("wanted ProviderNotFoundError, got: %v", err)
		}
	})

	t.Run("registered provider error", func(t *testing.T) {
		t.Parallel()

		testKeySchma := "myhero://"
		testKeyResourceID := testKeySchma + "deku"
		ErrorAssumingAllMight := errors.New("error assuming all might")

		// this init function only returns an error
		AddProvider("myhero://", func(_ context.Context, _ string, _ crypto.Hash, _ ...signature.RPCOption) (SignerVerifier, error) {
			return nil, ErrorAssumingAllMight
		})
		_, err := Get(testCtx, testKeyResourceID, testHashFunc)
		if diff := cmp.Diff(ErrorAssumingAllMight, err, cmpopts.EquateErrors()); diff != "" {
			t.Errorf("unexpected error (-want +got):\n%s", diff)
		}
	})

	t.Run("successful provider", func(t *testing.T) {
		t.Parallel()

		testKeySchma := "sac://"
		testKeyResourceID := testKeySchma + "2nd"
		testSignerVerifier := struct {
			SignerVerifier
		}{}
		var wantedErr error

		AddProvider(testKeySchma, func(_ context.Context, _ string, _ crypto.Hash, _ ...signature.RPCOption) (SignerVerifier, error) {
			return testSignerVerifier, nil
		})
		signerVerifier, err := Get(testCtx, testKeyResourceID, testHashFunc)
		if diff := cmp.Diff(wantedErr, err, cmpopts.EquateErrors()); diff != "" {
			t.Errorf("unexpected error (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff(testSignerVerifier, signerVerifier); diff != "" {
			t.Errorf("unexpected signer verifier (-want +got):\n%s", diff)
		}
	})
}
