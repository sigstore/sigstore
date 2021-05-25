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
	"log"
	"regexp"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/pkg/errors"
	"github.com/sigstore/sigstore/pkg/signature"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/ReneKroon/ttlcache/v2"
)

type KMSVersion struct {
	CryptoKeyVersion *kmspb.CryptoKeyVersion
	Signer           signature.SignerVerifier
}

type KMS struct {
	client        *kms.KeyManagementClient
	keyResourceID string
	projectID     string
	locationID    string
	keyRing       string
	key           string
	version       string
	kvCache       *ttlcache.Cache
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

func (g *KMS) kvCacheLoaderFunction(key string) (data interface{}, ttl time.Duration, err error) {
	// if we're given an explicit version, cache this value forever
	if g.version != "" {
		ttl = time.Second * 0
	} else {
		ttl = time.Second * 300
	}
	data, err = g.keyVersionName(context.Background())

	return
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
		kvCache:       ttlcache.NewCache(),
	}
	kms.kvCache.SetLoaderFunction(kms.kvCacheLoaderFunction)
	kms.kvCache.SkipTTLExtensionOnHit(true)

	// prime the cache
	_, err = kms.kvCache.Get(CacheKey)
	if err != nil {
		return nil, errors.Wrap(err, "initializing key version from GCP KMS")
	}

	return &kms, nil
}

func (g *KMS) Sign(rand io.Reader, payload []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx := context.Background()
	if sOpts, ok := opts.(signature.SignerOpts); ok {
		if sOpts.Context != nil {
			ctx = sOpts.Context
		}
	}
	return g.sign(ctx, payload)
}

func (g *KMS) Hasher() func(crypto.SignerOpts, []byte) ([]byte, crypto.Hash, error) {
	signer, err := g.getSigner()
	if err != nil {
		return func(crypto.SignerOpts, []byte) ([]byte, crypto.Hash, error) {
			return nil, 0, errors.Wrap(err, "getting signer for Hasher")
		}
	}
	return signer.Hasher()
}

func (g *KMS) generateSignRequest(payload []byte) (*kmspb.AsymmetricSignRequest, error) {
	// we get once and use consistently to ensure the cache value doesn't change underneath us
	kmsVersionInt, err := g.kvCache.Get(CacheKey)
	if err != nil {
		return nil, errors.Wrap(err, "getting KMSVersion from cache")
	}

	kmsVersion := kmsVersionInt.(*KMSVersion)
	// Calculate the digest of the message.
	digest, hasher, err := kmsVersion.Signer.Hasher()(nil, payload)
	if err != nil {
		return nil, errors.Wrap(err, "computing digest")
	}
	crc := crc32c(payload)

	req := &kmspb.AsymmetricSignRequest{
		Name:         kmsVersion.CryptoKeyVersion.Name,
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

// Optional but recommended: Compute digest's CRC32C.
func crc32c(data []byte) uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(data, t)
}

func (g *KMS) sign(ctx context.Context, rawPayload []byte) (signature []byte, err error) {
	req, err := g.generateSignRequest(rawPayload)
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

func (g *KMS) getSigner() (signature.SignerVerifier, error) {
	kmsVersion, err := g.kvCache.Get(CacheKey)
	if err != nil {
		return nil, errors.Wrap(err, "getting KMSVersion from cache")
	}
	return kmsVersion.(*KMSVersion).Signer, nil
}

func (g *KMS) Public() crypto.PublicKey {
	signer, err := g.getSigner()
	if err != nil {
		return nil
	}
	return signer.Public()
}

func (g *KMS) fetchPublicKey(ctx context.Context, name string) (crypto.PublicKey, error) {
	// Build the request.
	pkreq := &kmspb.GetPublicKeyRequest{Name: name}
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
func (g *KMS) keyVersionName(ctx context.Context) (*KMSVersion, error) {
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
	var kv *kmspb.CryptoKeyVersion
	if g.version != "" {
		req := &kmspb.GetCryptoKeyVersionRequest{
			Name: parent + fmt.Sprintf("/cryptoKeyVersions/%s", g.version),
		}
		kv, err = g.client.GetCryptoKeyVersion(ctx, req)
		if err != nil {
			return nil, err
		}
	} else {
		req := &kmspb.ListCryptoKeyVersionsRequest{
			Parent:  parent,
			Filter:  "state=ENABLED",
			OrderBy: "name desc",
		}
		iterator := g.client.ListCryptoKeyVersions(ctx, req)

		// pick the key version that is enabled with the greatest version value
		kv, err = iterator.Next()
		if err != nil {
			return nil, errors.Wrap(err, "unable to find an enabled key version in GCP KMS")
		}
	}
	// kv is keyVersion to use
	kmsVersion := KMSVersion{
		CryptoKeyVersion: kv,
	}

	pubKey, err := g.fetchPublicKey(ctx, kv.Name)
	if err != nil {
		return nil, errors.Wrap(err, "unable to fetch public key while creating signer")
	}

	switch kv.Algorithm {
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		kmsVersion.Signer = signature.NewECDSASignerVerifier(nil, pubKey.(*ecdsa.PublicKey), crypto.SHA256)
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		kmsVersion.Signer = signature.NewECDSASignerVerifier(nil, pubKey.(*ecdsa.PublicKey), crypto.SHA384)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256:
		kmsVersion.Signer = signature.NewRSASignerVerifier(nil, pubKey.(*rsa.PublicKey), crypto.SHA256)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512:
		kmsVersion.Signer = signature.NewRSASignerVerifier(nil, pubKey.(*rsa.PublicKey), crypto.SHA512)
	default:
		return nil, errors.New("unknown algorithm specified by KMS")
	}
	return &kmsVersion, nil
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
		log.Printf("Key ring %s already exists in GCP KMS, moving on to creating key.\n", result.GetName())
		// key ring already exists, no need to create
		return err
	}
	// try to create key ring
	createKeyRingRequest := &kmspb.CreateKeyRingRequest{
		Parent:    fmt.Sprintf("projects/%s/locations/%s", g.projectID, g.locationID),
		KeyRingId: g.keyRing,
	}
	result, err := g.client.CreateKeyRing(ctx, createKeyRingRequest)
	log.Printf("Created key ring %s in GCP KMS.\n", result.GetName())
	return err
}

func (g *KMS) createKey(ctx context.Context) (*ecdsa.PublicKey, error) {
	name := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", g.projectID, g.locationID, g.keyRing, g.key)
	getKeyRequest := &kmspb.GetCryptoKeyRequest{
		Name: name,
	}
	if result, err := g.client.GetCryptoKey(ctx, getKeyRequest); err == nil {
		log.Printf("Key %s already exists in GCP KMS, skipping creation.\n", result.GetName())
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
	log.Printf("Created key %s in GCP KMS\n", result.GetName())
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
	signer, err := g.getSigner()
	if err != nil {
		return errors.Wrap(err, "getting underlying signer")
	}
	return signer.VerifySignatureWithKey(publicKey, payload, signature)
}

func (g *KMS) VerifySignature(payload, signature []byte) error {
	if err := g.VerifySignatureWithKey(g.Public(), payload, signature); err != nil {
		// key could have been rotated, clear cache and try again if we're not pinned to a version
		if g.version == "" {
			_ = g.kvCache.Remove(CacheKey)
			return g.VerifySignatureWithKey(g.Public(), payload, signature)
		}
		return errors.Wrap(err, "failed to verify for fixed version")
	}
	return nil
}
