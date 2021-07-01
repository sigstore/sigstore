//
// Copyright 2021 The Sigstore Authors.
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

package signature

import (
	"bytes"
	"crypto"
	crand "crypto/rand"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature/options"
)

func testingSigner(t *testing.T, s Signer, alg string, hashFunc crypto.Hash, message []byte) {
	t.Helper()

	isED25519 := alg == "ed25519"

	var digest []byte
	if !isED25519 {
		hasher := hashFunc.New()
		_, _ = hasher.Write(message)
		digest = hasher.Sum(nil)
	}

	if _, err := s.SignMessage(nil); err == nil {
		t.Error("didn't error out for nil message")
	}

	// if nil is passed for rand, default (crypto/rand.Reader) should be used
	if _, err := s.SignMessage(bytes.NewReader(message), options.WithRand(nil)); err != nil && !isED25519 {
		t.Errorf("unexpected error passing nil Rand: %v", err)
	}

	if _, err := s.SignMessage(bytes.NewReader(message), options.WithRand(crand.Reader)); err != nil {
		t.Errorf("unexpected error passing valid Rand: %v", err)
	}

	if _, err := s.SignMessage(bytes.NewReader(message), options.WithRand(crand.Reader), options.WithDigest(digest)); err != nil {
		t.Errorf("unexpected error passing valid Rand and Digest: %v", err)
	}

	if _, err := s.SignMessage(bytes.NewReader(message), options.WithRand(crand.Reader), options.WithDigest(digest), options.WithCryptoSignerOpts(hashFunc)); err != nil {
		t.Errorf("unexpected error passing valid Rand and Digest and Opts: %v", err)
	}

	if _, err := s.SignMessage(bytes.NewReader(message), options.WithDigest(digest)); err != nil {
		t.Errorf("unexpected error passing valid Digest: %v", err)
	}

	if _, err := s.SignMessage(bytes.NewReader(message), options.WithDigest(digest), options.WithCryptoSignerOpts(crypto.Hash(0))); err == nil && !isED25519 {
		t.Error("no error passing invalid opts")
	}

	if _, err := s.SignMessage(bytes.NewReader(message), options.WithDigest(digest), options.WithCryptoSignerOpts(crypto.SHA512)); err == nil && !isED25519 {
		t.Error("no error passing mismatched Digest and opts")
	}

	if _, err := s.SignMessage(bytes.NewReader(message), options.WithCryptoSignerOpts(nil)); err != nil {
		t.Errorf("unexpected error passing nil options: %v", err)
	}

	// TODO: remove once Sign() method signature changes
	/*
		cs := s.(crypto.Signer)
		if _, err := cs.Sign(nil, nil, nil); err == nil {
			t.Errorf("no error passing nil for all args to Sign: %v", err)
		}

		if isED25519 {
			if _, err := cs.Sign(nil, message, crypto.Hash(0)); err != nil {
				t.Errorf("unexpected error passing nil Rand, message and crypto.Hash(0) to Sign: %v", err)
			}
		}

		if _, err := cs.Sign(nil, digest, nil); err != nil && !isED25519 {
			t.Errorf("unexpected error passing nil for Rand and Opts to Sign: %v", err)
		}

		if _, err := cs.Sign(nil, digest, &rsa.PSSOptions{Hash: hashFunc}); err != nil && !isED25519 {
			t.Errorf("unexpected error passing nil for Rand and valid Opts to Sign: %v", err)
		}

		if _, err := cs.Sign(crand.Reader, digest, &rsa.PSSOptions{Hash: hashFunc}); err != nil && !isED25519 {
			t.Errorf("unexpected error passing valid Rand and valid Opts to Sign: %v", err)
		}

		if _, err := cs.Sign(crand.Reader, digest, nil); err != nil && !isED25519 {
			t.Errorf("unexpected error passing valid Rand and nil Opts to Sign: %v", err)
		}

		if k := cs.Public(); k == nil {
			t.Error("Public() returned empty key")
		}

		if k, err := s.PublicKey(); k == nil || err != nil {
			t.Errorf("PublicKey() returned empty key or err: %v", err)
		}

		if k, err := s.PublicKey(options.WithContext(context.Background())); k == nil || err != nil {
			t.Errorf("PublicKey(context.Background()) returned empty key or err: %v", err)
		}
	*/
}

func testingVerifier(t *testing.T, v Verifier, alg string, hashFunc crypto.Hash, signature, message []byte) {
	t.Helper()

	isED25519 := alg == "ed25519"

	var digest []byte
	if !isED25519 {
		hasher := hashFunc.New()
		_, _ = hasher.Write(message)
		digest = hasher.Sum(nil)
	}

	if err := v.VerifySignature(bytes.NewReader(signature), nil); err == nil {
		t.Error("no error when passing nil as message")
	}

	if err := v.VerifySignature(nil, bytes.NewReader(message)); err == nil {
		t.Error("no error when passing nil as signature")
	}

	if err := v.VerifySignature(bytes.NewReader([]byte("not the sig")), bytes.NewReader(message)); err == nil {
		t.Error("no error when passing incorrect signature")
	}

	if err := v.VerifySignature(bytes.NewReader(signature), bytes.NewReader(message)); err != nil {
		t.Errorf("unexpected error when verifying valid bytes.NewReader(message): %v", err)
	}

	if err := v.VerifySignature(bytes.NewReader(signature), bytes.NewReader(message), options.WithDigest(digest)); err != nil {
		t.Errorf("unexpected error when using valid bytes.NewReader(message) with digest: %v", err)
	}

	if err := v.VerifySignature(bytes.NewReader(signature), bytes.NewReader(message), options.WithDigest(digest), options.WithCryptoSignerOpts(hashFunc)); err != nil {
		t.Errorf("unexpected error when using valid bytes.NewReader(message) with digest & opts: %v", err)
	}

	if err := v.VerifySignature(bytes.NewReader(signature), bytes.NewReader(message), options.WithDigest(digest), options.WithCryptoSignerOpts(crypto.SHA512)); err == nil && !isED25519 {
		t.Error("no error when using mismatched hashFunc with digest & opts")
	}
}
