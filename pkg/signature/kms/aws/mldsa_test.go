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

package aws

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/jellydator/ttlcache/v3"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeKMSKey struct {
	id       string
	spec     types.KeySpec
	alg      types.SigningAlgorithmSpec
	priv     crypto.Signer
	muToMsg  map[string][]byte
	lastSign *kms.SignInput
}

type fakeKMSClient struct {
	keys    map[string]*fakeKMSKey
	aliases map[string]string
	nextID  int
}

func newFakeKMSClient() *fakeKMSClient {
	return &fakeKMSClient{
		keys:    make(map[string]*fakeKMSKey),
		aliases: make(map[string]string),
	}
}

func (f *fakeKMSClient) resolve(keyID string) (*fakeKMSKey, error) {
	if target, ok := f.aliases[keyID]; ok {
		keyID = target
	}
	k, ok := f.keys[keyID]
	if !ok {
		return nil, &types.NotFoundException{Message: aws.String("key not found")}
	}
	return k, nil
}

func (f *fakeKMSClient) CreateKey(_ context.Context, params *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	var (
		priv crypto.Signer
		alg  types.SigningAlgorithmSpec
		err  error
	)
	switch params.KeySpec {
	case types.KeySpecMlDsa44:
		priv, err = mldsa.GenerateKey(mldsa.MLDSA44())
		alg = types.SigningAlgorithmSpecMlDsaShake256
	case types.KeySpecMlDsa65:
		priv, err = mldsa.GenerateKey(mldsa.MLDSA65())
		alg = types.SigningAlgorithmSpecMlDsaShake256
	case types.KeySpecMlDsa87:
		priv, err = mldsa.GenerateKey(mldsa.MLDSA87())
		alg = types.SigningAlgorithmSpecMlDsaShake256
	case types.KeySpecEccNistP256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		alg = types.SigningAlgorithmSpecEcdsaSha256
	default:
		return nil, fmt.Errorf("unsupported key spec in fake KMS: %s", params.KeySpec)
	}
	if err != nil {
		return nil, err
	}

	f.nextID++
	id := fmt.Sprintf("1234abcd-12ab-34cd-56ef-%012d", f.nextID)
	f.keys[id] = &fakeKMSKey{
		id:      id,
		spec:    params.KeySpec,
		alg:     alg,
		priv:    priv,
		muToMsg: make(map[string][]byte),
	}
	return &kms.CreateKeyOutput{
		KeyMetadata: &types.KeyMetadata{
			KeyId:             aws.String(id),
			KeySpec:           params.KeySpec,
			KeyUsage:          params.KeyUsage,
			SigningAlgorithms: []types.SigningAlgorithmSpec{alg},
		},
	}, nil
}

func (f *fakeKMSClient) CreateAlias(_ context.Context, params *kms.CreateAliasInput, _ ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
	f.aliases[aws.ToString(params.AliasName)] = aws.ToString(params.TargetKeyId)
	return &kms.CreateAliasOutput{}, nil
}

func (f *fakeKMSClient) DescribeKey(_ context.Context, params *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	k, err := f.resolve(aws.ToString(params.KeyId))
	if err != nil {
		return nil, err
	}
	return &kms.DescribeKeyOutput{
		KeyMetadata: &types.KeyMetadata{
			KeyId:             aws.String(k.id),
			KeySpec:           k.spec,
			KeyUsage:          types.KeyUsageTypeSignVerify,
			SigningAlgorithms: []types.SigningAlgorithmSpec{k.alg},
		},
	}, nil
}

func (f *fakeKMSClient) GetPublicKey(_ context.Context, params *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	k, err := f.resolve(aws.ToString(params.KeyId))
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(k.priv.Public())
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{
		KeyId:             aws.String(k.id),
		KeySpec:           k.spec,
		KeyUsage:          types.KeyUsageTypeSignVerify,
		PublicKey:         der,
		SigningAlgorithms: []types.SigningAlgorithmSpec{k.alg},
	}, nil
}

func (f *fakeKMSClient) Sign(_ context.Context, params *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	k, err := f.resolve(aws.ToString(params.KeyId))
	if err != nil {
		return nil, err
	}
	k.lastSign = params

	switch params.SigningAlgorithm {
	case types.SigningAlgorithmSpecMlDsaShake256:
		if params.MessageType != types.MessageTypeExternalMu {
			return nil, fmt.Errorf("expected EXTERNAL_MU for ML-DSA, got %s", params.MessageType)
		}
		if len(params.Message) != 64 {
			return nil, fmt.Errorf("expected 64-byte mu for EXTERNAL_MU, got %d bytes", len(params.Message))
		}
		mldsaPriv, ok := k.priv.(*mldsa.PrivateKey)
		if !ok {
			return nil, errors.New("key is not mldsa")
		}
		sig, err := mldsaPriv.Sign(nil, params.Message, crypto.MLDSAMu)
		if err != nil {
			return nil, err
		}
		return &kms.SignOutput{
			KeyId:            aws.String(k.id),
			Signature:        sig,
			SigningAlgorithm: params.SigningAlgorithm,
		}, nil
	case types.SigningAlgorithmSpecEcdsaSha256:
		if params.MessageType != types.MessageTypeDigest {
			return nil, fmt.Errorf("expected DIGEST for ECDSA, got %s", params.MessageType)
		}
		ecPriv, ok := k.priv.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("key is not ecdsa")
		}
		sig, err := ecdsa.SignASN1(rand.Reader, ecPriv, params.Message)
		if err != nil {
			return nil, err
		}
		return &kms.SignOutput{
			KeyId:            aws.String(k.id),
			Signature:        sig,
			SigningAlgorithm: params.SigningAlgorithm,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported signing algorithm: %s", params.SigningAlgorithm)
	}
}

func (f *fakeKMSClient) Verify(_ context.Context, params *kms.VerifyInput, _ ...func(*kms.Options)) (*kms.VerifyOutput, error) {
	k, err := f.resolve(aws.ToString(params.KeyId))
	if err != nil {
		return nil, err
	}
	switch params.SigningAlgorithm {
	case types.SigningAlgorithmSpecMlDsaShake256:
		if params.MessageType != types.MessageTypeExternalMu {
			return nil, fmt.Errorf("expected EXTERNAL_MU for ML-DSA verify, got %s", params.MessageType)
		}
		if len(params.Message) != 64 {
			return nil, fmt.Errorf("expected 64-byte mu for EXTERNAL_MU verify, got %d bytes", len(params.Message))
		}
		origMsg, ok := k.muToMsg[string(params.Message)]
		if !ok {
			return nil, &types.KMSInvalidSignatureException{Message: aws.String("unknown mu / signature invalid")}
		}
		pub, ok := k.priv.Public().(*mldsa.PublicKey)
		if !ok {
			return nil, errors.New("key is not mldsa")
		}
		if err := mldsa.Verify(pub, origMsg, params.Signature, nil); err != nil {
			return nil, &types.KMSInvalidSignatureException{Message: aws.String(err.Error())}
		}
		return &kms.VerifyOutput{
			KeyId:            aws.String(k.id),
			SignatureValid:   true,
			SigningAlgorithm: params.SigningAlgorithm,
		}, nil
	case types.SigningAlgorithmSpecEcdsaSha256:
		if params.MessageType != types.MessageTypeDigest {
			return nil, fmt.Errorf("expected DIGEST for ECDSA verify, got %s", params.MessageType)
		}
		pub, ok := k.priv.Public().(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("key is not ecdsa")
		}
		if !ecdsa.VerifyASN1(pub, params.Message, params.Signature) {
			return nil, &types.KMSInvalidSignatureException{Message: aws.String("invalid signature")}
		}
		return &kms.VerifyOutput{
			KeyId:            aws.String(k.id),
			SignatureValid:   true,
			SigningAlgorithm: params.SigningAlgorithm,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported signing algorithm: %s", params.SigningAlgorithm)
	}
}

func newTestSignerVerifier(fake *fakeKMSClient, alias string) *SignerVerifier {
	return &SignerVerifier{
		client: &awsClient{
			client: fake,
			keyID:  alias,
			alias:  alias,
			keyCache: ttlcache.New(
				ttlcache.WithDisableTouchOnHit[string, cmk](),
			),
		},
	}
}

func TestSupportedAlgorithmsIncludesMLDSA(t *testing.T) {
	sv := &SignerVerifier{}
	algs := sv.SupportedAlgorithms()
	assert.Contains(t, algs, string(types.KeySpecMlDsa44))
	assert.Contains(t, algs, string(types.KeySpecMlDsa65))
	assert.Contains(t, algs, string(types.KeySpecMlDsa87))
	assert.Contains(t, algs, string(types.KeySpecEccNistP256))
	assert.Equal(t, string(types.KeySpecEccNistP256), sv.DefaultAlgorithm())
}

func TestMLDSACreateSignVerify(t *testing.T) {
	tests := []struct {
		name       string
		spec       types.KeySpec
		wantParams mldsa.Parameters
	}{
		{name: "ML-DSA-44", spec: types.KeySpecMlDsa44, wantParams: mldsa.MLDSA44()},
		{name: "ML-DSA-65", spec: types.KeySpecMlDsa65, wantParams: mldsa.MLDSA65()},
		{name: "ML-DSA-87", spec: types.KeySpecMlDsa87, wantParams: mldsa.MLDSA87()},
	}

	messages := []struct {
		name string
		data []byte
	}{
		{name: "short", data: []byte("hello sigstore ml-dsa")},
		{name: "empty", data: []byte{}},
		{name: "larger-than-4096", data: bytes.Repeat([]byte("a"), 10000)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fake := newFakeKMSClient()
			alias := "alias/" + tc.name
			sv := newTestSignerVerifier(fake, alias)

			pub, err := sv.CreateKey(ctx, string(tc.spec))
			require.NoError(t, err)
			mldsaPub, ok := pub.(*mldsa.PublicKey)
			require.True(t, ok, "expected *mldsa.PublicKey, got %T", pub)
			assert.Equal(t, tc.wantParams, mldsaPub.Parameters())

			fetchedPub, err := sv.PublicKey(options.WithContext(ctx))
			require.NoError(t, err)
			assert.True(t, mldsaPub.Equal(fetchedPub))

			key, err := fake.resolve(alias)
			require.NoError(t, err)

			for _, msg := range messages {
				t.Run(msg.name, func(t *testing.T) {
					sig, err := sv.SignMessage(bytes.NewReader(msg.data), options.WithContext(ctx))
					require.NoError(t, err)
					require.NotEmpty(t, sig)

					// Verify Sign sent EXTERNAL_MU with 64-byte mu
					require.NotNil(t, key.lastSign)
					assert.Equal(t, types.MessageTypeExternalMu, key.lastSign.MessageType)
					assert.Equal(t, types.SigningAlgorithmSpecMlDsaShake256, key.lastSign.SigningAlgorithm)
					assert.Len(t, key.lastSign.Message, 64)

					// Record mu -> raw message mapping for fake remote Verify
					key.muToMsg[string(key.lastSign.Message)] = msg.data

					// Local verification using Go stdlib crypto/mldsa proves mu matches FIPS 204
					require.NoError(t, sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg.data), options.WithContext(ctx)))

					// Remote verification using EXTERNAL_MU
					require.NoError(t, sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg.data), options.WithContext(ctx), options.WithRemoteVerification(true)))

					// Tampered message must fail both locally and remotely
					tampered := append(append([]byte{}, msg.data...), 'x')
					assert.Error(t, sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(tampered), options.WithContext(ctx)))
					assert.Error(t, sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(tampered), options.WithContext(ctx), options.WithRemoteVerification(true)))
				})
			}

			// WithDigest carrying raw message + crypto.Hash(0) works for SignMessage and remote VerifySignature
			rawMsg := []byte("raw message via WithDigest")
			sig, err := sv.SignMessage(nil, options.WithContext(ctx), options.WithDigest(rawMsg), options.WithCryptoSignerOpts(crypto.Hash(0)))
			require.NoError(t, err)
			key.muToMsg[string(key.lastSign.Message)] = rawMsg
			require.NoError(t, sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(rawMsg), options.WithContext(ctx)))
			require.NoError(t, sv.VerifySignature(bytes.NewReader(sig), nil, options.WithContext(ctx), options.WithDigest(rawMsg), options.WithCryptoSignerOpts(crypto.Hash(0)), options.WithRemoteVerification(true)))
		})
	}
}

func TestMLDSACryptoSignerAndX509(t *testing.T) {
	ctx := context.Background()
	fake := newFakeKMSClient()
	sv := newTestSignerVerifier(fake, "alias/mldsa-x509")

	_, err := sv.CreateKey(ctx, string(types.KeySpecMlDsa65))
	require.NoError(t, err)

	cs, signerOpts, err := sv.CryptoSigner(ctx, func(err error) {
		t.Errorf("unexpected CryptoSigner error: %v", err)
	})
	require.NoError(t, err)
	assert.Equal(t, crypto.Hash(0), signerOpts.HashFunc())

	// Direct crypto.Signer.Sign with nil opts, crypto.Hash(0), &mldsa.Options{}, and empty message
	for _, tc := range []struct {
		name string
		msg  []byte
		opts crypto.SignerOpts
	}{
		{name: "nil-opts", msg: []byte("msg"), opts: nil},
		{name: "hash-zero", msg: []byte("msg"), opts: crypto.Hash(0)},
		{name: "empty-mldsa-opts", msg: []byte("msg"), opts: &mldsa.Options{}},
		{name: "empty-message", msg: []byte{}, opts: crypto.Hash(0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := cs.Sign(rand.Reader, tc.msg, tc.opts)
			require.NoError(t, err)
			pub, ok := cs.Public().(*mldsa.PublicKey)
			require.True(t, ok)
			require.NoError(t, mldsa.Verify(pub, tc.msg, sig, nil))
		})
	}

	// Self-signed X.509 certificate via crypto/x509.CreateCertificate
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sigstore-aws-mldsa-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	derCert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, cs.Public(), cs)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(derCert)
	require.NoError(t, err)
	require.NoError(t, cert.CheckSignatureFrom(cert))
}

func TestMLDSAUnsupportedOptions(t *testing.T) {
	ctx := context.Background()
	fake := newFakeKMSClient()
	sv := newTestSignerVerifier(fake, "alias/mldsa-opts")

	_, err := sv.CreateKey(ctx, string(types.KeySpecMlDsa44))
	require.NoError(t, err)

	msg := []byte("test message")
	digest := sha256.Sum256(msg)

	// SignMessage must reject non-zero hash funcs and non-empty ML-DSA context
	_, err = sv.SignMessage(bytes.NewReader(msg), options.WithContext(ctx), options.WithCryptoSignerOpts(crypto.SHA256))
	assert.Error(t, err)

	_, err = sv.SignMessage(nil, options.WithContext(ctx), options.WithDigest(digest[:]), options.WithCryptoSignerOpts(crypto.SHA256))
	assert.Error(t, err)

	_, err = sv.SignMessage(bytes.NewReader(msg), options.WithContext(ctx), options.WithCryptoSignerOpts(crypto.MLDSAMu))
	assert.Error(t, err)

	_, err = sv.SignMessage(bytes.NewReader(msg), options.WithContext(ctx), options.WithCryptoSignerOpts(&mldsa.Options{Context: "non-empty"}))
	assert.Error(t, err)

	// Remote VerifySignature must reject non-zero hash funcs and non-empty ML-DSA context
	sig, err := sv.SignMessage(bytes.NewReader(msg), options.WithContext(ctx))
	require.NoError(t, err)

	err = sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg), options.WithContext(ctx), options.WithRemoteVerification(true), options.WithCryptoSignerOpts(crypto.SHA256))
	assert.Error(t, err)

	err = sv.VerifySignature(bytes.NewReader(sig), nil, options.WithContext(ctx), options.WithDigest(digest[:]), options.WithRemoteVerification(true), options.WithCryptoSignerOpts(crypto.SHA256))
	assert.Error(t, err)

	err = sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg), options.WithContext(ctx), options.WithRemoteVerification(true), options.WithCryptoSignerOpts(&mldsa.Options{Context: "non-empty"}))
	assert.Error(t, err)

	// CryptoSigner.Sign must reject non-empty context, non-zero hash, MLDSAMu, and nil message
	cs, _, err := sv.CryptoSigner(ctx, nil)
	require.NoError(t, err)

	_, err = cs.Sign(rand.Reader, msg, &mldsa.Options{Context: "non-empty"})
	assert.Error(t, err)

	_, err = cs.Sign(rand.Reader, digest[:], crypto.SHA256)
	assert.Error(t, err)

	_, err = cs.Sign(rand.Reader, make([]byte, 64), crypto.MLDSAMu)
	assert.Error(t, err)

	_, err = cs.Sign(rand.Reader, nil, crypto.Hash(0))
	assert.Error(t, err)
}

func TestECDSARejectsHashZero(t *testing.T) {
	ctx := context.Background()
	fake := newFakeKMSClient()
	sv := newTestSignerVerifier(fake, "alias/ecdsa-test")

	_, err := sv.CreateKey(ctx, string(types.KeySpecEccNistP256))
	require.NoError(t, err)

	msg := []byte("hello ecdsa")
	sig, err := sv.SignMessage(bytes.NewReader(msg), options.WithContext(ctx))
	require.NoError(t, err)
	require.NoError(t, sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg), options.WithContext(ctx)))
	require.NoError(t, sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg), options.WithContext(ctx), options.WithRemoteVerification(true)))

	// ECDSA key must reject crypto.Hash(0)
	_, err = sv.SignMessage(bytes.NewReader(msg), options.WithContext(ctx), options.WithCryptoSignerOpts(crypto.Hash(0)))
	assert.Error(t, err)

	err = sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg), options.WithContext(ctx), options.WithRemoteVerification(true), options.WithCryptoSignerOpts(crypto.Hash(0)))
	assert.Error(t, err)
}

func TestComputeMLDSAMuKAT(t *testing.T) {
	// Deterministic FIPS 204 seed expanded via crypto/mldsa.NewPrivateKey;
	// expected 64-byte mu values independently computed with SHAKE256 per
	// FIPS 204 Section 6.2: tr = SHAKE256(pk, 64), mu = SHAKE256(tr || 0x00 || 0x00 || msg, 64).
	seed := bytes.Repeat([]byte{0x42}, mldsa.PrivateKeySize)

	tests := []struct {
		name       string
		params     mldsa.Parameters
		msg        []byte
		expectedMu string
	}{
		{
			name:       "ML-DSA-44/empty",
			params:     mldsa.MLDSA44(),
			msg:        []byte{},
			expectedMu: "4cf60aadb0151c1315381ac261f48c92030c0754e67e22e5d0adb533e27c74b51b9dc34b6bb1faedcd1eaea02c57c9567d0a5b00330b885920cdcfe6a96e7d49",
		},
		{
			name:       "ML-DSA-44/message",
			params:     mldsa.MLDSA44(),
			msg:        []byte("sigstore external mu test"),
			expectedMu: "2810b1018ab95e1283bcb1b269bda479837107b9982f74c08b5656ab919ed209cdc5853b15180ad6e1b64add1e46c0dd98ff92f4582169a166409b3a400a223c",
		},
		{
			name:       "ML-DSA-65/empty",
			params:     mldsa.MLDSA65(),
			msg:        []byte{},
			expectedMu: "f802f1499000198c3f399a542839cf62ae1e8e62015907ab2ceab5f65c61d835408714c65ec250566502725e7fb71d0f9cc724e7f79ee8e4617c3b5dc3f90200",
		},
		{
			name:       "ML-DSA-65/message",
			params:     mldsa.MLDSA65(),
			msg:        []byte("sigstore external mu test"),
			expectedMu: "7b6c8b9ec29ac630f7df5ce9a9ae8a951606aea69068e2a66b03031b1de676f4f88a58e004671071ae8682fc1d1bff3fb398e39288b02274247643ad773f0211",
		},
		{
			name:       "ML-DSA-87/empty",
			params:     mldsa.MLDSA87(),
			msg:        []byte{},
			expectedMu: "0635eec0f97083212ad7c9bf7c68146a32edd94d3054b94fab170706dc2c5dc0818eab50ff0d8776877b13694db92e372da541ad795305bb9aa434a2d6b3862c",
		},
		{
			name:       "ML-DSA-87/message",
			params:     mldsa.MLDSA87(),
			msg:        []byte("sigstore external mu test"),
			expectedMu: "c519998421e554c138a53a3fec240aeb56c92e1740ec9eb7ce8ecd60d2bf71b04ad5374c6c22933e131b3bba24045e662a20528dfbae93b5684a358b12c0a71f",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := mldsa.NewPrivateKey(tc.params, seed)
			require.NoError(t, err)
			pub := priv.PublicKey()

			mu, err := computeMLDSAMu(pub, tc.msg)
			require.NoError(t, err)
			require.Len(t, mu, 64)
			assert.Equal(t, tc.expectedMu, hex.EncodeToString(mu))

			// Cross-check with Go stdlib crypto/mldsa: signing mu via crypto.MLDSAMu
			// must verify against the raw message via mldsa.Verify (which computes mu internally).
			sig, err := priv.Sign(nil, mu, crypto.MLDSAMu)
			require.NoError(t, err)
			assert.NoError(t, mldsa.Verify(pub, tc.msg, sig, nil))
		})
	}
}

func TestComputeMLDSAMuProperties(t *testing.T) {
	t.Run("nil public key rejected", func(t *testing.T) {
		_, err := computeMLDSAMu(nil, []byte("hello"))
		assert.Error(t, err)
	})

	paramSets := []struct {
		name   string
		params mldsa.Parameters
	}{
		{"ML-DSA-44", mldsa.MLDSA44()},
		{"ML-DSA-65", mldsa.MLDSA65()},
		{"ML-DSA-87", mldsa.MLDSA87()},
	}

	messages := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"leading-zero-byte", []byte{0x00}},
		{"double-zero-bytes", []byte{0x00, 0x00}},
		{"single-byte", []byte{0xff}},
		{"4095-bytes", bytes.Repeat([]byte("a"), 4095)},
		{"4096-bytes", bytes.Repeat([]byte("b"), 4096)},
		{"4097-bytes", bytes.Repeat([]byte("c"), 4097)},
		{"100KiB", bytes.Repeat([]byte("d"), 100*1024)},
	}

	for _, ps := range paramSets {
		t.Run(ps.name, func(t *testing.T) {
			priv, err := mldsa.GenerateKey(ps.params)
			require.NoError(t, err)
			pub := priv.PublicKey()

			for _, m := range messages {
				t.Run(m.name, func(t *testing.T) {
					mu, err := computeMLDSAMu(pub, m.data)
					require.NoError(t, err)
					require.Len(t, mu, 64)

					// Deterministic
					mu2, err := computeMLDSAMu(pub, m.data)
					require.NoError(t, err)
					assert.Equal(t, mu, mu2)

					// Signing mu with crypto.MLDSAMu verifies as pure ML-DSA with empty context
					sig, err := priv.Sign(nil, mu, crypto.MLDSAMu)
					require.NoError(t, err)
					assert.NoError(t, mldsa.Verify(pub, m.data, sig, nil))

					// Must fail verification with non-empty context (proves 0x00, 0x00 empty-context prefix)
					assert.Error(t, mldsa.Verify(pub, m.data, sig, &mldsa.Options{Context: "ctx"}))

					// Must fail verification on modified message
					modified := append(bytes.Clone(m.data), 0x01)
					assert.Error(t, mldsa.Verify(pub, modified, sig, nil))
				})
			}

			// nil and empty slice must produce identical mu
			muNil, err := computeMLDSAMu(pub, nil)
			require.NoError(t, err)
			muEmpty, err := computeMLDSAMu(pub, []byte{})
			require.NoError(t, err)
			assert.Equal(t, muNil, muEmpty)

			// Empty message must differ from []byte{0x00} (no ambiguity with 0x00, 0x00 prefix)
			muZero, err := computeMLDSAMu(pub, []byte{0x00})
			require.NoError(t, err)
			assert.NotEqual(t, muEmpty, muZero)

			// Domain separation: mu must differ from SHAKE256(msg, 64) and SHAKE256(tr || msg, 64)
			msg := []byte("domain separation check")
			muMsg, err := computeMLDSAMu(pub, msg)
			require.NoError(t, err)

			rawShake := sha3.SumSHAKE256(msg, 64)
			assert.NotEqual(t, rawShake, muMsg)

			tr := sha3.SumSHAKE256(pub.Bytes(), 64)
			noPrefix := sha3.NewSHAKE256()
			_, _ = noPrefix.Write(tr)
			_, _ = noPrefix.Write(msg)
			muNoPrefix := make([]byte, 64)
			_, _ = noPrefix.Read(muNoPrefix)
			assert.NotEqual(t, muNoPrefix, muMsg)

			// Public key binding: distinct keys must yield distinct mu for the same message
			priv2, err := mldsa.GenerateKey(ps.params)
			require.NoError(t, err)
			pub2 := priv2.PublicKey()
			muOtherKey, err := computeMLDSAMu(pub2, msg)
			require.NoError(t, err)
			assert.NotEqual(t, muMsg, muOtherKey)
		})
	}
}
