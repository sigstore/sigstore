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

package gcp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"io"
	"regexp"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/pkg/errors"
	"github.com/sigstore/sigstore/pkg/signature"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/ReneKroon/ttlcache/v2"
)

type KMS struct {
	client        *kms.KeyManagementClient
	keyResourceID string
	projectID     string
	locationID    string
	keyRing       string
	key           string
	version       string
	keyVersion    *kmspb.CryptoKeyVersion
	signer        signature.SignerVerifier
	pubKeyCache   *ttlcache.Cache
}

var (
	ErrKMSReference = errors.New("kms specification should be in the format gcpkms://projects/[PROJECT_ID]/locations/[LOCATION]/keyRings/[KEY_RING]/cryptoKeys/[KEY]/versions/[VERSION]")

	re = regexp.MustCompile(`^gcpkms://projects/([^/]+)/locations/([^/]+)/keyRings/([^/]+)/cryptoKeys/([^/]+)(?:/versions/([^/]+))?$`)
)

// use a consistent key for cache lookups
const CacheKey = "public_key"

// schemes for various KMS services are copied from https://github.com/google/go-cloud/tree/master/secrets
const ReferenceScheme = "gcpkms://"

func ValidReference(ref string) error {
	if !re.MatchString(ref) {
		return ErrKMSReference
	}
	return nil
}

func parseReference(resourceID string) (projectID, locationID, keyRing, keyName, version string, err error) {
	v := re.FindStringSubmatch(resourceID)
	if len(v) != 6 {
		err = errors.Errorf("invalid gcpkms format %q", resourceID)
		return
	}
	projectID, locationID, keyRing, keyName, version = v[1], v[2], v[3], v[4], v[5]
	return
}

func (g *KMS) pubKeyCacheLoaderFunction(key string) (data interface{}, ttl time.Duration, err error) {
	ttl = time.Second * 300
	data, err = g.publicKey(context.Background())

	return data, ttl, err
}

func NewGCP(ctx context.Context, keyResourceID string) (*KMS, error) {
	projectID, locationID, keyRing, keyName, version, err := parseReference(keyResourceID)
	if err != nil {
		return nil, err
	}

	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "new gcp kms client")
	}

	kms := KMS{
		client:        client,
		keyResourceID: keyResourceID,
		projectID:     projectID,
		locationID:    locationID,
		keyRing:       keyRing,
		key:           keyName,
		version:       version,
		pubKeyCache:   ttlcache.NewCache(),
	}
	kms.pubKeyCache.SetLoaderFunction(kms.pubKeyCacheLoaderFunction)
	kms.pubKeyCache.SkipTTLExtensionOnHit(true)

	kms.keyVersion, err = kms.keyVersionName(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "fetching key version from GCP KMS")
	}

	if err = kms.createSigner(); err != nil {
		return nil, errors.Wrap(err, "fetching key version from GCP KMS")
	}

	return &kms, nil
}

func (g *KMS) createSigner() error {
	if g.keyVersion == nil {
		return errors.New("key version object not initialized")
	}

	pubKey := g.Public()
	if pubKey == nil {
		return errors.New("unable to fetch public key while creating signer")
	}

	switch g.keyVersion.Algorithm {
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		g.signer = signature.NewECDSASignerVerifier(nil, pubKey.(*ecdsa.PublicKey), crypto.SHA256)
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		g.signer = signature.NewECDSASignerVerifier(nil, pubKey.(*ecdsa.PublicKey), crypto.SHA384)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256:
		g.signer = signature.NewRSASignerVerifier(nil, pubKey.(*rsa.PublicKey), crypto.SHA256)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512:
		g.signer = signature.NewRSASignerVerifier(nil, pubKey.(*rsa.PublicKey), crypto.SHA512)
	default:
		return errors.New("unknown algorithm specified by KMS")
	}
	return nil
}

func (g *KMS) Sign(rand io.Reader, payload []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx := context.Background()
	if sOpts, ok := opts.(signature.SignerOpts); ok {
		ctx = sOpts.Context
	}
	return g.sign(ctx, payload)
}

func (g *KMS) Hasher() func(crypto.SignerOpts, []byte) ([]byte, crypto.Hash, error) {
	return g.signer.Hasher()
}

func (g *KMS) generateSignRequest(digest []byte, hasher crypto.Hash, crc uint32) (*kmspb.AsymmetricSignRequest, error) {
	if g.keyVersion == nil {
		return nil, errors.New("keyVersion has not been initialized")
	}
	req := &kmspb.AsymmetricSignRequest{
		Name:         g.keyVersion.Name,
		Digest:       &kmspb.Digest{},
		DigestCrc32C: wrapperspb.Int64(int64(crc)),
	}
	switch hasher {
	case crypto.SHA256:
		req.Digest.Digest = &kmspb.Digest_Sha256{
			Sha256: digest,
		}
	case crypto.SHA384:
		req.Digest.Digest = &kmspb.Digest_Sha384{
			Sha384: digest,
		}
	case crypto.SHA512:
		req.Digest.Digest = &kmspb.Digest_Sha512{
			Sha512: digest,
		}
	default:
		return nil, errors.New("unsupported hashing algorithm")
	}
	return req, nil
}

func (g *KMS) sign(ctx context.Context, rawPayload []byte) (signature []byte, err error) {
	// Calculate the digest of the message.
	digest, hasher, err := g.Hasher()(nil, rawPayload)
	if err != nil {
		return nil, errors.Wrap(err, "computing digest")
	}
	// Optional but recommended: Compute digest's CRC32C.
	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)
	}
	req, err := g.generateSignRequest(digest, hasher, crc32c(digest))
	if err != nil {
		return nil, err
	}

	result, err := g.client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, err
	}
	// Optional, but recommended: perform integrity verification on result.
	// For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
	// https://cloud.google.com/kms/docs/data-integrity-guidelines
	if !result.VerifiedDigestCrc32C {
		return nil, fmt.Errorf("AsymmetricSign: request corrupted in-transit")
	}
	if int64(crc32c(result.Signature)) != result.SignatureCrc32C.Value {
		return nil, fmt.Errorf("AsymmetricSign: response corrupted in-transit")
	}
	return result.GetSignature(), nil
}

func (g *KMS) Public() crypto.PublicKey {
	key, err := g.pubKeyCache.Get(CacheKey)
	if err != nil {
		return nil
	}
	return key.(crypto.PublicKey)
}

func (g *KMS) publicKey(ctx context.Context) (crypto.PublicKey, error) {
	// Build the request.
	pkreq := &kmspb.GetPublicKeyRequest{Name: g.keyVersion.Name}
	// Call the API.
	pk, err := g.client.GetPublicKey(ctx, pkreq)
	if err != nil {
		return nil, errors.Wrap(err, "public key")
	}
	p, _ := pem.Decode([]byte(pk.GetPem()))
	if p == nil {
		return nil, errors.New("pem.Decode failed")
	}
	publicKey, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse public key")
	}
	return publicKey, nil
}

func (g *KMS) ECDSAPublicKey() (*ecdsa.PublicKey, error) {
	k := g.Public()
	if k == nil {
		return nil, errors.New("unable to obtain public key")
	}
	ecPub, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key was not ECDSA: %#v", k)
	}
	return ecPub, nil
}

// keyVersionName returns the first key version found for a key in KMS
// TODO: is there a better way to do this?
func (g *KMS) keyVersionName(ctx context.Context) (*kmspb.CryptoKeyVersion, error) {
	parent := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", g.projectID, g.locationID, g.keyRing, g.key)

	parentReq := &kmspb.GetCryptoKeyRequest{
		Name: parent,
	}
	key, err := g.client.GetCryptoKey(ctx, parentReq)
	if err != nil {
		return nil, err
	}
	if key.Purpose != kmspb.CryptoKey_ASYMMETRIC_SIGN {
		return nil, errors.New("specified key cannot be used to sign")
	}

	// if g.version was specified, use it explicitly
	if g.version != "" {
		req := &kmspb.GetCryptoKeyVersionRequest{
			Name: parent + fmt.Sprintf("/cryptoKeyVersions/%s", g.version),
		}
		return g.client.GetCryptoKeyVersion(ctx, req)
	}

	req := &kmspb.ListCryptoKeyVersionsRequest{
		Parent:  parent,
		Filter:  "state=ENABLED",
		OrderBy: "name desc",
	}
	iterator := g.client.ListCryptoKeyVersions(ctx, req)

	// pick the key version that is enabled with the greatest version value
	kv, err := iterator.Next()
	if err != nil {
		return nil, errors.New("unable to find an enabled key version in GCP KMS")
	}
	return kv, nil
}

//TODO: make these more generic for different algorithms (RSA/ECDSA)
func (g *KMS) CreateKey(ctx context.Context) (*ecdsa.PublicKey, error) {
	if err := g.createKeyRing(ctx); err != nil {
		return nil, errors.Wrap(err, "creating key ring")
	}
	return g.createKey(ctx)
}

func (g *KMS) createKeyRing(ctx context.Context) error {
	getKeyRingRequest := &kmspb.GetKeyRingRequest{
		Name: fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", g.projectID, g.locationID, g.keyRing),
	}
	if result, err := g.client.GetKeyRing(ctx, getKeyRingRequest); err == nil {
		fmt.Printf("Key ring %s already exists in GCP KMS, moving on to creating key.\n", result.GetName())
		// key ring already exists, no need to create
		return err
	}
	// try to create key ring
	createKeyRingRequest := &kmspb.CreateKeyRingRequest{
		Parent:    fmt.Sprintf("projects/%s/locations/%s", g.projectID, g.locationID),
		KeyRingId: g.keyRing,
	}
	result, err := g.client.CreateKeyRing(ctx, createKeyRingRequest)
	fmt.Printf("Created key ring %s in GCP KMS.\n", result.GetName())
	return err
}

func (g *KMS) createKey(ctx context.Context) (*ecdsa.PublicKey, error) {
	name := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", g.projectID, g.locationID, g.keyRing, g.key)
	getKeyRequest := &kmspb.GetCryptoKeyRequest{
		Name: name,
	}
	if result, err := g.client.GetCryptoKey(ctx, getKeyRequest); err == nil {
		fmt.Printf("Key %s already exists in GCP KMS, skipping creation.\n", result.GetName())
		pub, err := g.ECDSAPublicKey()
		if err != nil {
			return nil, errors.Wrap(err, "retrieving public key")
		}
		return pub, nil
	}
	createKeyRequest := &kmspb.CreateCryptoKeyRequest{
		Parent:      fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", g.projectID, g.locationID, g.keyRing),
		CryptoKeyId: g.key,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
			},
		},
	}
	result, err := g.client.CreateCryptoKey(ctx, createKeyRequest)
	if err != nil {
		return nil, errors.Wrap(err, "creating crypto key")
	}
	fmt.Printf("Created key %s in GCP KMS\n", result.GetName())
	pub, err := g.ECDSAPublicKey()
	if err != nil {
		return nil, errors.Wrap(err, "retrieving public key")
	}
	return pub, nil
}

func (g *KMS) VerifySignatureWithKey(publicKey crypto.PublicKey, payload, signature []byte) error {
	if publicKey == nil {
		return errors.New("invalid public key specified")
	}
	return g.signer.VerifySignatureWithKey(publicKey, payload, signature)
}

func (g *KMS) VerifySignature(payload, signature []byte) error {
	if err := g.VerifySignatureWithKey(g.Public(), payload, signature); err != nil {
		// key could have been rotated, clear cache and try again
		g.pubKeyCache.Remove(CacheKey)
		return g.VerifySignatureWithKey(g.Public(), payload, signature)
	}
	return nil
}
