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

package azure

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/jellydator/ttlcache/v3"
)

// These tests exercise the full SignMessage -> VerifySignature round-trip using
// *real* crypto, via a kvClient mock that mimics Azure Key Vault: for EC keys it
// returns/consumes a fixed-width r||s signature, and for RSA keys a PKCS#1 v1.5
// signature. The existing testKVClient in client_test.go is a no-op (Verify
// always succeeds), so it cannot catch signature (un)wrapping bugs. These tests
// can, and guard against regressions like an incorrect ASN.1 -> r||s conversion.

func hashForDigestLen(n int) crypto.Hash {
	switch n {
	case 48:
		return crypto.SHA384
	case 64:
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

func azCurveName(c elliptic.Curve) azkeys.CurveName {
	switch c {
	case elliptic.P384():
		return azkeys.CurveNameP384
	case elliptic.P521():
		return azkeys.CurveNameP521
	default:
		return azkeys.CurveNameP256
	}
}

func signVerifyKeyOps() []*azkeys.KeyOperation {
	return []*azkeys.KeyOperation{
		to.Ptr(azkeys.KeyOperationSign),
		to.Ptr(azkeys.KeyOperationVerify),
	}
}

// realCryptoKVClient performs actual ECDSA/RSA signing and verification,
// mirroring Azure Key Vault's raw signature formats.
type realCryptoKVClient struct {
	testKVClient
	ec  *ecdsa.PrivateKey
	rsa *rsa.PrivateKey
}

func (c *realCryptoKVClient) GetKey(_ context.Context, _, _ string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	kid := azkeys.ID("https://honk-vault.vault.azure.net/keys/honk-key/abc123")
	jwk := &azkeys.JSONWebKey{KID: &kid, KeyOps: signVerifyKeyOps()}
	switch {
	case c.ec != nil:
		size := (c.ec.Curve.Params().BitSize + 7) / 8
		x := make([]byte, size)
		y := make([]byte, size)
		c.ec.X.FillBytes(x)
		c.ec.Y.FillBytes(y)
		jwk.Kty = to.Ptr(azkeys.KeyTypeEC)
		jwk.Crv = to.Ptr(azCurveName(c.ec.Curve))
		jwk.X = x
		jwk.Y = y
	case c.rsa != nil:
		jwk.Kty = to.Ptr(azkeys.KeyTypeRSA)
		jwk.N = c.rsa.N.Bytes()
		jwk.E = big.NewInt(int64(c.rsa.E)).Bytes()
	}
	return azkeys.GetKeyResponse{KeyBundle: azkeys.KeyBundle{Key: jwk}}, nil
}

func (c *realCryptoKVClient) Sign(_ context.Context, _, _ string, params azkeys.SignParameters, _ *azkeys.SignOptions) (azkeys.SignResponse, error) {
	digest := params.Value
	var raw []byte
	if c.ec != nil {
		r, s, err := ecdsa.Sign(rand.Reader, c.ec, digest)
		if err != nil {
			return azkeys.SignResponse{}, err
		}
		size := (c.ec.Curve.Params().BitSize + 7) / 8
		raw = make([]byte, 2*size)
		r.FillBytes(raw[:size])
		s.FillBytes(raw[size:])
	} else {
		var err error
		raw, err = rsa.SignPKCS1v15(rand.Reader, c.rsa, hashForDigestLen(len(digest)), digest)
		if err != nil {
			return azkeys.SignResponse{}, err
		}
	}
	return azkeys.SignResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: raw}}, nil
}

func (c *realCryptoKVClient) Verify(_ context.Context, _, _ string, params azkeys.VerifyParameters, _ *azkeys.VerifyOptions) (azkeys.VerifyResponse, error) {
	ok := false
	if c.ec != nil {
		// Azure requires a fixed-width r||s; reject anything else, exactly as
		// the real service does. This makes the padding behaviour observable.
		size := (c.ec.Curve.Params().BitSize + 7) / 8
		if len(params.Signature) == 2*size {
			r := new(big.Int).SetBytes(params.Signature[:size])
			s := new(big.Int).SetBytes(params.Signature[size:])
			ok = ecdsa.Verify(&c.ec.PublicKey, params.Digest, r, s)
		}
	} else {
		ok = rsa.VerifyPKCS1v15(&c.rsa.PublicKey, hashForDigestLen(len(params.Digest)), params.Digest, params.Signature) == nil
	}
	return azkeys.VerifyResponse{KeyVerifyResult: azkeys.KeyVerifyResult{Value: &ok}}, nil
}

func newSignerVerifier(t *testing.T, client kvClient) *SignerVerifier {
	t.Helper()
	return &SignerVerifier{
		defaultCtx: context.Background(),
		client: &azureVaultClient{
			client: client,
			keyCache: ttlcache.New[string, crypto.PublicKey](
				ttlcache.WithDisableTouchOnHit[string, crypto.PublicKey](),
			),
		},
	}
}

func TestVerifySignatureRoundTrip(t *testing.T) {
	newEC := func(curve elliptic.Curve) kvClient {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("generating EC key: %v", err)
		}
		return &realCryptoKVClient{ec: priv}
	}
	newRSA := func(bits int) kvClient {
		priv, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatalf("generating RSA key: %v", err)
		}
		return &realCryptoKVClient{rsa: priv}
	}

	tests := []struct {
		name   string
		client kvClient
	}{
		{"EC-P256", newEC(elliptic.P256())},
		{"EC-P384", newEC(elliptic.P384())},
		{"EC-P521", newEC(elliptic.P521())},
		{"RSA-2048", newRSA(2048)},
		{"RSA-3072", newRSA(3072)},
		{"RSA-4096", newRSA(4096)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sv := newSignerVerifier(t, tc.client)
			// Multiple iterations: EC r/s vary per signature, so any
			// coordinate mixup is caught with overwhelming probability.
			for i := 0; i < 10; i++ {
				msg := []byte("azure kms round-trip test message")
				sig, err := sv.SignMessage(bytes.NewReader(msg))
				if err != nil {
					t.Fatalf("SignMessage: %v", err)
				}
				if err := sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg)); err != nil {
					t.Fatalf("VerifySignature failed on a valid signature: %v", err)
				}
			}
		})
	}
}

// encodingAssertKVClient checks that VerifySignature reconstructs the raw EC
// signature as a fixed-width r||s with the correct r and s values, regardless of
// whether the signature is cryptographically valid. This deterministically
// guards both the r/s ordering and the leading-zero padding.
type encodingAssertKVClient struct {
	testKVClient
	pub          *ecdsa.PublicKey
	wantR, wantS *big.Int
	coordSize    int
}

func (c *encodingAssertKVClient) GetKey(_ context.Context, _, _ string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	x := make([]byte, c.coordSize)
	y := make([]byte, c.coordSize)
	c.pub.X.FillBytes(x)
	c.pub.Y.FillBytes(y)
	kid := azkeys.ID("https://honk-vault.vault.azure.net/keys/honk-key/abc123")
	return azkeys.GetKeyResponse{KeyBundle: azkeys.KeyBundle{Key: &azkeys.JSONWebKey{
		KID:    &kid,
		Kty:    to.Ptr(azkeys.KeyTypeEC),
		Crv:    to.Ptr(azCurveName(c.pub.Curve)),
		X:      x,
		Y:      y,
		KeyOps: signVerifyKeyOps(),
	}}}, nil
}

func (c *encodingAssertKVClient) Verify(_ context.Context, _, _ string, params azkeys.VerifyParameters, _ *azkeys.VerifyOptions) (azkeys.VerifyResponse, error) {
	ok := len(params.Signature) == 2*c.coordSize &&
		new(big.Int).SetBytes(params.Signature[:c.coordSize]).Cmp(c.wantR) == 0 &&
		new(big.Int).SetBytes(params.Signature[c.coordSize:]).Cmp(c.wantS) == 0
	return azkeys.VerifyResponse{KeyVerifyResult: azkeys.KeyVerifyResult{Value: &ok}}, nil
}

// TestVerifySignatureECFixedWidthEncoding deterministically checks that an
// ASN.1 signature whose s has a leading zero byte is reconstructed to a
// full-width r||s (not truncated), and that r and s are not swapped/duplicated.
func TestVerifySignatureECFixedWidthEncoding(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	const coordSize = 32

	// r: full width (high bit set). s: small, so s.Bytes() is only 1 byte and
	// must be left-padded to 32 bytes.
	r := new(big.Int).SetBytes(bytes.Repeat([]byte{0xAB}, coordSize))
	s := big.NewInt(1)

	sigDER, err := asn1.Marshal(struct{ R, S *big.Int }{R: r, S: s})
	if err != nil {
		t.Fatalf("marshaling ASN.1 signature: %v", err)
	}

	sv := newSignerVerifier(t, &encodingAssertKVClient{
		pub:       &priv.PublicKey,
		wantR:     r,
		wantS:     s,
		coordSize: coordSize,
	})

	if err := sv.VerifySignature(bytes.NewReader(sigDER), bytes.NewReader([]byte("msg"))); err != nil {
		t.Fatalf("expected full-width r||s reconstruction, got error: %v", err)
	}
}
