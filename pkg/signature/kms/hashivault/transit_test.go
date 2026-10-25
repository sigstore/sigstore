//
// Copyright 2026 The Sigstore Authors.
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

package hashivault

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mldsaKeyStyle renders the fake's ML-DSA key read response in a particular server
// dialect. OpenBao names one key type per parameter set. Vault enterprise names
// version entries "ml-dsa-<set>" and reports type "ml-dsa" and the parameter_set
// at the top level of the response. The bare "ml-dsa" styles cover an entry name
// without the set, with parameter_set in the version entry or at the top level.
var (
	mldsaOpenBao44 = mldsaKeyStyle{name: AlgorithmMLDSA44}
	mldsaOpenBao65 = mldsaKeyStyle{name: AlgorithmMLDSA65}
	mldsaOpenBao87 = mldsaKeyStyle{name: AlgorithmMLDSA87}
	mldsaVault65   = mldsaKeyStyle{name: AlgorithmMLDSA65FB, topType: AlgorithmMLDSA, parameterSet: "65", paramAtTop: true}
	mldsaBareEntry = mldsaKeyStyle{name: AlgorithmMLDSA, parameterSet: "65"}
	mldsaBareTop   = mldsaKeyStyle{name: AlgorithmMLDSA, parameterSet: json.Number("65"), paramAtTop: true}
)

type mldsaKeyStyle struct {
	name         string // name field of the version entry
	topType      string // type field at the top level of the read response, "" for none
	parameterSet any    // parameter_set value, nil when the dialect has none
	paramAtTop   bool   // render parameter_set at the top level of the read response
}

// transitRequest is one sign or verify request received by fakeTransit.
type transitRequest struct {
	path      string
	prehashed bool
	input     []byte
}

// createRequest is one key-create body received by fakeTransit.
type createRequest struct {
	keyType      string
	parameterSet string
}

// createMode controls how fakeTransit responds to key-create writes.
type createMode int

const (
	createAccept              createMode = iota // every accepted form succeeds immediately
	createRequireVaultDialect                   // OpenBao form → 400, ml-dsa + parameter_set accepted
	createForbidden                             // 403 on everything, no retry permitted
)

// fakeTransit emulates the Vault/OpenBao transit endpoints this provider uses, for a single key
// named "test-key" backed by an in-memory private key. Like the real servers, it signs input as a
// digest for ECDSA keys and as the message for Ed25519 and ML-DSA keys (Ed25519ph when prehashed).
type fakeTransit struct {
	t          *testing.T
	privateKey crypto.Signer
	mldsaStyle mldsaKeyStyle
	createMode createMode

	mu       sync.Mutex
	requests []transitRequest
	creates  []createRequest
}

func (f *fakeTransit) keyEntry() map[string]any {
	entry := map[string]any{}
	switch pub := f.privateKey.Public().(type) {
	case ed25519.PublicKey:
		entry["name"] = "ed25519"
		entry["public_key"] = base64.StdEncoding.EncodeToString(pub)
	case *mldsa.PublicKey:
		entry["name"] = f.mldsaStyle.name
		if !f.mldsaStyle.paramAtTop {
			entry["parameter_set"] = f.mldsaStyle.parameterSet
		}
		entry["public_key"] = base64.StdEncoding.EncodeToString(pub.Bytes())
	default:
		pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(f.privateKey.Public())
		require.NoError(f.t, err)
		entry["name"] = "P-256"
		entry["public_key"] = string(pemBytes)
	}
	return entry
}

// transitEndpoint reports whether path is exactly one of the sign or verify
// endpoints this provider builds, with the optional hash suffix. Matching exactly,
// rather than by prefix or with URL normalization, keeps the emulator able to catch
// reverted request formatting such as a doubled slash (verify/k//sha2-256) or a
// trailing slash (verify/k/). Note that the vault API client normalizes request
// paths before the wire (path.Join in api/client.go), so exact matching guards the
// provider's request-building format rather than what the server would observe.
func transitEndpoint(action, path string) bool {
	if rest := strings.TrimPrefix(path, "/v1/transit/"+action+"/test-key"); len(rest) != len(path) {
		return rest == "" || rest == "/sha2-256" || rest == "/sha2-512"
	}
	return false
}

func (f *fakeTransit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	reply := func(data map[string]any) {
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(f.t, json.NewEncoder(w).Encode(map[string]any{"data": data}))
	}
	errorReply := func(status int, messages ...string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		assert.NoError(f.t, json.NewEncoder(w).Encode(map[string]any{"errors": messages}))
	}
	switch {
	case r.Method == http.MethodGet && path == "/v1/transit/keys/test-key":
		data := map[string]any{"latest_version": 1, "keys": map[string]any{"1": f.keyEntry()}}
		if _, ok := f.privateKey.Public().(*mldsa.PublicKey); ok {
			if f.mldsaStyle.topType != "" {
				data["type"] = f.mldsaStyle.topType
			}
			if f.mldsaStyle.paramAtTop {
				data["parameter_set"] = f.mldsaStyle.parameterSet
			}
		}
		reply(data)
	case r.Method == http.MethodPut || r.Method == http.MethodPost:
		raw, err := io.ReadAll(r.Body)
		if !assert.NoError(f.t, err) {
			return
		}
		var body struct {
			Input     string `json:"input"`
			Prehashed bool   `json:"prehashed"`
			Signature string `json:"signature"`
		}
		if !assert.NoError(f.t, json.Unmarshal(raw, &body)) {
			return
		}
		input, err := base64.StdEncoding.DecodeString(body.Input)
		if !assert.NoError(f.t, err) {
			return
		}
		f.recordRequest(transitRequest{path: path, prehashed: body.Prehashed, input: input})

		switch {
		case transitEndpoint("sign", path):
			sig, err := f.sign(input, body.Prehashed)
			if !assert.NoError(f.t, err) {
				return
			}
			reply(map[string]any{"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(sig)})
		case transitEndpoint("verify", path):
			sig, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(body.Signature, "vault:v1:"))
			if !assert.NoError(f.t, err) {
				return
			}
			reply(map[string]any{"valid": f.verify(input, sig, body.Prehashed)})
		case path == "/v1/transit/keys/test-key":
			var create struct {
				Type         string `json:"type"`
				ParameterSet string `json:"parameter_set"`
			}
			if !assert.NoError(f.t, json.Unmarshal(raw, &create)) {
				return
			}
			f.recordCreate(createRequest{keyType: create.Type, parameterSet: create.ParameterSet})

			switch f.createMode {
			case createAccept:
				// Like OpenBao: any accepted form succeeds immediately.
				reply(map[string]any{})
			case createRequireVaultDialect:
				// Like Vault enterprise: the OpenBao per-set form is a validation
				// error (400); the ml-dsa + parameter_set form is accepted.
				if create.Type == AlgorithmMLDSA && create.ParameterSet != "" {
					reply(map[string]any{})
				} else {
					errorReply(http.StatusBadRequest, "invalid key type: "+create.Type)
				}
			case createForbidden:
				// Not a validation error: must fail without triggering the fallback.
				errorReply(http.StatusForbidden, "permission denied")
			}
		default:
			http.NotFound(w, r)
		}
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeTransit) recordRequest(req transitRequest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req)
}

func (f *fakeTransit) recordCreate(req createRequest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates = append(f.creates, req)
}

func (f *fakeTransit) createLog() []createRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.creates)
}

func (f *fakeTransit) sign(input []byte, prehashed bool) ([]byte, error) {
	switch k := f.privateKey.(type) {
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, k, input)
	case ed25519.PrivateKey:
		// Prehashed Ed25519 (Ed25519ph) follows the documented transit protocol,
		// which HashiCorp Vault >= 1.19 currently refuses (hashicorp/vault#31574);
		// OpenBao and Vault <= 1.18 accept it.
		if prehashed {
			return k.Sign(rand.Reader, input, &ed25519.Options{Hash: crypto.SHA512})
		}
		return k.Sign(rand.Reader, input, crypto.Hash(0))
	case *mldsa.PrivateKey:
		// Pure ML-DSA with an empty context, like the real servers.
		return k.Sign(rand.Reader, input, nil)
	default:
		return nil, errors.New("unsupported test key")
	}
}

func (f *fakeTransit) verify(input, sig []byte, prehashed bool) bool {
	switch pub := f.privateKey.Public().(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(pub, input, sig)
	case ed25519.PublicKey:
		opts := &ed25519.Options{}
		if prehashed {
			opts.Hash = crypto.SHA512
		}
		return ed25519.VerifyWithOptions(pub, input, sig, opts) == nil
	case *mldsa.PublicKey:
		return mldsa.Verify(pub, input, sig, nil) == nil
	default:
		return false
	}
}

func (f *fakeTransit) lastRequest(t *testing.T) transitRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.requests)
	return f.requests[len(f.requests)-1]
}

// loadFake starts a fakeTransit for key and loads a SignerVerifier for it with hashFunc, the way
// callers that do not know the key type load it. The ML-DSA key is rendered in the OpenBao dialect.
func loadFake(t *testing.T, key crypto.Signer, hashFunc crypto.Hash) (*SignerVerifier, *fakeTransit) {
	return loadFakeStyle(t, key, hashFunc, mldsaOpenBao65)
}

func loadFakeStyle(t *testing.T, key crypto.Signer, hashFunc crypto.Hash, style mldsaKeyStyle) (*SignerVerifier, *fakeTransit) {
	t.Helper()
	fake := &fakeTransit{t: t, privateKey: key, mldsaStyle: style}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	sv, err := LoadSignerVerifier("hashivault://test-key", hashFunc,
		options.WithRPCAuthOpts(options.RPCAuth{Address: server.URL, Token: "test-token"}))
	require.NoError(t, err)
	return sv, fake
}

// TestPureModeKeysSignTheRawMessage checks that ML-DSA and pure Ed25519 keys
// sign and verify the raw message, whatever hash the caller loaded or passed
// per call. ML-DSA runs against every key-read dialect; the Ed25519 entry name
// is dialect-independent.
func TestPureModeKeysSignTheRawMessage(t *testing.T) {
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mldsaKey44, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	mldsaKey65, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	mldsaKey87, err := mldsa.GenerateKey(mldsa.MLDSA87())
	require.NoError(t, err)
	message := []byte("the raw message")

	for _, c := range []struct {
		name  string
		key   crypto.Signer
		style mldsaKeyStyle
	}{
		{"ed25519", ed25519Key, mldsaOpenBao65},
		{"ML-DSA-44", mldsaKey44, mldsaOpenBao44},
		{"ML-DSA-65", mldsaKey65, mldsaOpenBao65},
		{"ML-DSA-87", mldsaKey87, mldsaOpenBao87},
		{"ML-DSA-65/vault", mldsaKey65, mldsaVault65},
		{"ML-DSA-65/bare-ml-dsa-entry", mldsaKey65, mldsaBareEntry},
		{"ML-DSA-65/bare-ml-dsa-top", mldsaKey65, mldsaBareTop},
	} {
		t.Run(c.name, func(t *testing.T) {
			// Loaded with SHA-256, as callers that do not know the key type do.
			sv, fake := loadFakeStyle(t, c.key, crypto.SHA256, c.style)

			pub, err := sv.PublicKey()
			require.NoError(t, err)
			assert.NoError(t, cryptoutils.EqualKeys(c.key.Public(), pub))

			sig, err := sv.SignMessage(bytes.NewReader(message))
			require.NoError(t, err)
			req := fake.lastRequest(t)
			assert.Equal(t, "/v1/transit/sign/test-key", req.path)
			assert.False(t, req.prehashed)
			assert.Equal(t, message, req.input)

			// The signature verifies locally, over the raw message (PureEd25519 / ML-DSA verifiers).
			verifier, err := signature.LoadVerifier(pub, crypto.Hash(0))
			require.NoError(t, err)
			assert.NoError(t, verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(message)))

			// Remote verification sends the raw message too, on a path without a trailing slash.
			assert.NoError(t, sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(message)))
			req = fake.lastRequest(t)
			assert.Equal(t, "/v1/transit/verify/test-key", req.path)
			assert.False(t, req.prehashed)
			assert.Equal(t, message, req.input)
			assert.Error(t, sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader([]byte("another message"))))

			// A per-call hash option does not turn a pure-mode signature into a digest signature.
			_, err = sv.SignMessage(bytes.NewReader(message), options.WithCryptoSignerOpts(crypto.SHA256))
			require.NoError(t, err)
			assert.Equal(t, message, fake.lastRequest(t).input)

			// A precomputed digest cannot be used: pure modes require the message itself.
			digest := sha256.Sum256(message)
			_, err = sv.SignMessage(nil, options.WithDigest(digest[:]), options.WithCryptoSignerOpts(crypto.SHA256))
			assert.Error(t, err)
			assert.Error(t, sv.VerifySignature(bytes.NewReader(sig), nil, options.WithDigest(digest[:]), options.WithCryptoSignerOpts(crypto.SHA256)))

			// Paired with crypto.Hash(0), the crypto.Signer convention applies and the
			// WithDigest bytes carry the message itself.
			sig, err = sv.SignMessage(nil, options.WithDigest(message), options.WithCryptoSignerOpts(crypto.Hash(0)))
			require.NoError(t, err)
			assert.Equal(t, message, fake.lastRequest(t).input)
			assert.NoError(t, verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(message)))
			assert.NoError(t, sv.VerifySignature(bytes.NewReader(sig), nil, options.WithDigest(message), options.WithCryptoSignerOpts(crypto.Hash(0))))

			// The crypto.Signer view asks for the message itself.
			signer, signerOpts, err := sv.CryptoSigner(context.Background(), nil)
			require.NoError(t, err)
			assert.Equal(t, crypto.Hash(0), signerOpts.HashFunc())
			sig, err = signer.Sign(rand.Reader, message, signerOpts)
			require.NoError(t, err)
			assert.Equal(t, message, fake.lastRequest(t).input)
			assert.NoError(t, verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(message)))
		})
	}
}

// TestWhichMldsa checks that ML-DSA key detection handles both the OpenBao and the
// Vault enterprise response dialects, wherever the parameter set is carried, and
// that ML-DSA key types it cannot map are errors rather than "not ML-DSA".
func TestWhichMldsa(t *testing.T) {
	for _, c := range []struct {
		name        string
		entry       map[string]any
		topParamSet any
		wantParams  mldsa.Parameters
		wantIsMLDSA bool
		wantErr     string
	}{
		{
			name:        "openbao per-set names",
			entry:       map[string]any{"name": AlgorithmMLDSA44},
			wantParams:  mldsa.MLDSA44(),
			wantIsMLDSA: true,
		},
		{
			// What Vault enterprise's key read returns: the set in the entry name,
			// with parameter_set (and type) also at the top level of the response.
			name:        "vault enterprise key read",
			entry:       map[string]any{"name": AlgorithmMLDSA65FB},
			topParamSet: "65",
			wantParams:  mldsa.MLDSA65(),
			wantIsMLDSA: true,
		},
		{
			name:        "vault enterprise entry name 44",
			entry:       map[string]any{"name": AlgorithmMLDSA44FB},
			wantParams:  mldsa.MLDSA44(),
			wantIsMLDSA: true,
		},
		{
			name:        "vault enterprise entry name 65",
			entry:       map[string]any{"name": AlgorithmMLDSA65FB},
			wantParams:  mldsa.MLDSA65(),
			wantIsMLDSA: true,
		},
		{
			name:        "vault enterprise entry name 87",
			entry:       map[string]any{"name": AlgorithmMLDSA87FB},
			wantParams:  mldsa.MLDSA87(),
			wantIsMLDSA: true,
		},
		{
			name:        "bare ml-dsa entry parameter_set",
			entry:       map[string]any{"name": AlgorithmMLDSA, "parameter_set": "87"},
			wantParams:  mldsa.MLDSA87(),
			wantIsMLDSA: true,
		},
		{
			name:        "bare ml-dsa entry parameter_set as json.Number",
			entry:       map[string]any{"name": AlgorithmMLDSA, "parameter_set": json.Number("65")},
			wantParams:  mldsa.MLDSA65(),
			wantIsMLDSA: true,
		},
		{
			name:        "bare ml-dsa top-level parameter_set",
			entry:       map[string]any{"name": AlgorithmMLDSA},
			topParamSet: "44",
			wantParams:  mldsa.MLDSA44(),
			wantIsMLDSA: true,
		},
		{
			name:        "bare ml-dsa top-level parameter_set as json.Number",
			entry:       map[string]any{"name": AlgorithmMLDSA},
			topParamSet: json.Number("87"),
			wantParams:  mldsa.MLDSA87(),
			wantIsMLDSA: true,
		},
		{
			name:        "entry parameter_set takes priority over top level",
			entry:       map[string]any{"name": AlgorithmMLDSA, "parameter_set": "65"},
			topParamSet: "44",
			wantParams:  mldsa.MLDSA65(),
			wantIsMLDSA: true,
		},
		{
			name:        "bare ml-dsa without parameter_set",
			entry:       map[string]any{"name": AlgorithmMLDSA},
			wantIsMLDSA: true,
			wantErr:     `ML-DSA key type "ml-dsa" has no parameter_set`,
		},
		{
			name:        "bare ml-dsa parameter_set of an unusable type",
			entry:       map[string]any{"name": AlgorithmMLDSA, "parameter_set": true},
			wantIsMLDSA: true,
			wantErr:     `ML-DSA key type "ml-dsa" has no parameter_set`,
		},
		{
			name:        "bare ml-dsa unknown entry parameter_set",
			entry:       map[string]any{"name": AlgorithmMLDSA, "parameter_set": "63"},
			wantIsMLDSA: true,
			wantErr:     `unsupported ML-DSA parameter set "63" for key type "ml-dsa"`,
		},
		{
			name:        "bare ml-dsa unknown top-level parameter_set",
			entry:       map[string]any{"name": AlgorithmMLDSA},
			topParamSet: json.Number("128"),
			wantIsMLDSA: true,
			wantErr:     `unsupported ML-DSA parameter set "128" for key type "ml-dsa"`,
		},
		{
			name:        "unknown openbao-style name",
			entry:       map[string]any{"name": "mldsa-99"},
			wantIsMLDSA: true,
			wantErr:     `unsupported ML-DSA key type "mldsa-99"`,
		},
		{
			name:        "unknown vault-style per-set name",
			entry:       map[string]any{"name": "ml-dsa-128"},
			wantIsMLDSA: true,
			wantErr:     `unsupported ML-DSA key type "ml-dsa-128"`,
		},
		{
			name:  "ed25519",
			entry: map[string]any{"name": "ed25519"},
		},
		{
			name:  "missing name",
			entry: map[string]any{},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			params, isMLDSA, err := whichMldsa(c.entry, c.topParamSet)
			assert.Equal(t, c.wantIsMLDSA, isMLDSA)
			if c.wantErr != "" {
				assert.EqualError(t, err, c.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.wantParams, params)
		})
	}
}

// TestUnrecognizedMLDSAKeyTypesAreRejected checks that an ML-DSA key the provider
// cannot map surfaces that problem from PublicKey, instead of the misleading PEM
// error it produced when such keys fell through to PEM parsing.
func TestUnrecognizedMLDSAKeyTypesAreRejected(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	for _, c := range []struct {
		name    string
		style   mldsaKeyStyle
		wantErr string
	}{
		{"unknown key type", mldsaKeyStyle{name: "mldsa-99"}, `unsupported ML-DSA key type "mldsa-99"`},
		{"unknown parameter set", mldsaKeyStyle{name: AlgorithmMLDSA, parameterSet: "63"}, `unsupported ML-DSA parameter set "63"`},
		{"missing parameter set", mldsaKeyStyle{name: AlgorithmMLDSA}, `has no parameter_set`},
	} {
		t.Run(c.name, func(t *testing.T) {
			sv, _ := loadFakeStyle(t, key, crypto.SHA256, c.style)
			_, err := sv.PublicKey()
			require.Error(t, err)
			assert.Contains(t, err.Error(), c.wantErr)
			assert.NotContains(t, err.Error(), "PEM")
		})
	}
}

func TestECDSAKeysSignADigest(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	message := []byte("the raw message")
	sv, fake := loadFake(t, key, crypto.SHA256)

	sig, err := sv.SignMessage(bytes.NewReader(message))
	require.NoError(t, err)
	req := fake.lastRequest(t)
	assert.Equal(t, "/v1/transit/sign/test-key/sha2-256", req.path)
	assert.True(t, req.prehashed)
	digest := sha256.Sum256(message)
	assert.Equal(t, digest[:], req.input)

	verifier, err := signature.LoadECDSAVerifier(&key.PublicKey, crypto.SHA256)
	require.NoError(t, err)
	assert.NoError(t, verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(message)))

	assert.NoError(t, sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(message)))
	assert.Equal(t, "/v1/transit/verify/test-key/sha2-256", fake.lastRequest(t).path)
}

func TestEd25519phWithSHA512(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	message := []byte("the raw message")
	sv, fake := loadFake(t, key, crypto.SHA512)

	sig, err := sv.SignMessage(bytes.NewReader(message))
	require.NoError(t, err)
	req := fake.lastRequest(t)
	assert.Equal(t, "/v1/transit/sign/test-key/sha2-512", req.path)
	assert.True(t, req.prehashed)

	verifier, err := signature.LoadVerifierWithOpts(key.Public(), options.WithED25519ph())
	require.NoError(t, err)
	assert.NoError(t, verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(message)))

	// The crypto.Signer view keeps the Ed25519ph semantics: callers hash with SHA-512.
	_, signerOpts, err := sv.CryptoSigner(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, crypto.SHA512, signerOpts.HashFunc())
}

// TestLegacyDigestFormEd25519SignaturesAreRejected makes the pre-MR behavior change
// deliberate and visible: providers before this MR signed sha256(message) as a pure
// Ed25519 signature, and their remote verify applied the same transform, so such
// artifacts verified through the KMS (though never with a local pure verifier).
// They no longer verify; artifacts have to be re-signed.
func TestLegacyDigestFormEd25519SignaturesAreRejected(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	message := []byte("the legacy message")
	sv, fake := loadFake(t, key, crypto.SHA256)

	digest := sha256.Sum256(message)
	sig := ed25519.Sign(key, digest[:])
	err = sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(message))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed vault verification")
	// Verification is performed over the raw message: it is the old-format signature
	// that is rejected, not a different request shape.
	assert.Equal(t, message, fake.lastRequest(t).input)
}

func TestCryptoSignerRejectsSigningContext(t *testing.T) {
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	for _, c := range []struct {
		name string
		key  crypto.Signer
		opts crypto.SignerOpts
	}{
		{"ML-DSA context", mldsaKey, &mldsa.Options{Context: "ctx"}},
		{"Ed25519 context", ed25519Key, &ed25519.Options{Context: "ctx"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			sv, fake := loadFakeStyle(t, c.key, crypto.SHA256, mldsaOpenBao65)
			signer, _, err := sv.CryptoSigner(context.Background(), nil)
			require.NoError(t, err)
			_, err = signer.Sign(rand.Reader, []byte("message"), c.opts)
			assert.Error(t, err)
			// Rejected at the wrapper, before anything is signed.
			assert.Empty(t, fake.requests)
		})
	}
}

// TestCreateKeyFallback checks that the Vault enterprise create form is only
// retried for request-validation failures, never for other errors.
func TestCreateKeyFallback(t *testing.T) {
	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	for _, c := range []struct {
		name        string
		createMode  createMode
		wantCreates []createRequest
		wantErr     bool
	}{
		{
			// OpenBao accepts the OpenBao form directly.
			name:        "first attempt accepted",
			createMode:  createAccept,
			wantCreates: []createRequest{{keyType: AlgorithmMLDSA65}},
		},
		{
			// Vault enterprise refuses the OpenBao form with a 400: the fallback
			// retries with type ml-dsa plus the parameter_set field.
			name:        "fallback after 400",
			createMode:  createRequireVaultDialect,
			wantCreates: []createRequest{{keyType: AlgorithmMLDSA65}, {keyType: AlgorithmMLDSA, parameterSet: "65"}},
		},
		{
			// Any other failure must not trigger the fallback, and the original
			// error must be reported instead of a disguised one.
			name:        "no fallback without a 400",
			createMode:  createForbidden,
			wantCreates: []createRequest{{keyType: AlgorithmMLDSA65}},
			wantErr:     true,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Helper()
			fake := &fakeTransit{t: t, privateKey: mldsaKey, mldsaStyle: mldsaOpenBao65, createMode: c.createMode}
			server := httptest.NewServer(fake)
			t.Cleanup(server.Close)
			sv, err := LoadSignerVerifier("hashivault://test-key", crypto.SHA256,
				options.WithRPCAuthOpts(options.RPCAuth{Address: server.URL, Token: "test-token"}))
			require.NoError(t, err)

			pub, err := sv.CreateKey(context.Background(), AlgorithmMLDSA65)
			assert.Equal(t, c.wantCreates, fake.createLog())
			if c.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "failed to create transit key")
				assert.NotContains(t, err.Error(), "retrying as vault enterprise ml-dsa")
			} else {
				require.NoError(t, err)
				_, ok := pub.(*mldsa.PublicKey)
				assert.True(t, ok)
			}
		})
	}
}
