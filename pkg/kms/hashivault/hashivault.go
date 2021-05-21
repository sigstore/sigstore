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

package hashivault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ReneKroon/ttlcache/v2"
	vault "github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
)

type KMS struct {
	client      *vault.Client
	keyPath     string
	pubKeyCache *ttlcache.Cache
}

var (
	errReference   = errors.New("kms specification should be in the format hashivault://<key>")
	referenceRegex = regexp.MustCompile(`^hashivault://(?P<path>\w(([\w-.]+)?\w)?)$`)
)

const (
	hashAlg = "sha2-256"
	signAlg = "sha2-256"

	vaultV1DataPrefix = "vault:v1:"
)

// use a consistent key for cache lookups
const CacheKey = "public_key"

const ReferenceScheme = "hashivault://"

func ValidReference(ref string) error {
	if !referenceRegex.MatchString(ref) {
		return errReference
	}
	return nil
}

func parseReference(resourceID string) (keyPath string, err error) {
	i := referenceRegex.SubexpIndex("path")
	v := referenceRegex.FindStringSubmatch(resourceID)
	if len(v) < i+1 {
		err = errors.Errorf("invalid vault format %q", resourceID)
		return
	}
	keyPath = v[i]
	return
}

func NewVault(ctx context.Context, keyResourceID string) (*KMS, error) {
	keyPath, err := parseReference(keyResourceID)
	if err != nil {
		return nil, err
	}

	address := os.Getenv("VAULT_ADDR")
	if address == "" {
		return nil, errors.New("VAULT_ADDR is not set")
	}

	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		return nil, errors.New("VAULT_TOKEN is not set")
	}

	client, err := vault.NewClient(&vault.Config{
		Address: address,
	})
	if err != nil {
		return nil, errors.Wrap(err, "new vault client")
	}

	kms := KMS{
		client:      client,
		keyPath:     keyPath,
		pubKeyCache: ttlcache.NewCache(),
	}
	kms.pubKeyCache.SetLoaderFunction(kms.pubKeyCacheLoaderFunction)
	kms.pubKeyCache.SkipTTLExtensionOnHit(true)

	return &kms, nil
}

func (g *KMS) pubKeyCacheLoaderFunction(key string) (data interface{}, ttl time.Duration, err error) {
	ttl = time.Second * 300
	data, err = g.publicKey(context.Background())

	return data, ttl, err
}

func (g *KMS) Sign(_ io.Reader, payload []byte, _ crypto.SignerOpts) ([]byte, error) {
	sig, _, err := g.sign(context.TODO(), payload)
	return sig, err
}

func (g *KMS) sign(_ context.Context, rawPayload []byte) (signature, signed []byte, err error) {
	client := g.client.Logical()

	hash := sha256.Sum256(rawPayload)
	signed = hash[:]

	signResult, err := client.Write(fmt.Sprintf("/transit/sign/%s/%s", g.keyPath, signAlg), map[string]interface{}{
		"input":     base64.StdEncoding.Strict().EncodeToString(signed),
		"prehashed": true,
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, "Transit: failed to sign payload")
	}

	encodedSignature, ok := signResult.Data["signature"]
	if !ok {
		return nil, nil, errors.New("Transit: response corrupted in-transit")
	}

	signature, err = vaultDecode(encodedSignature)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Transit: response corrupted in-transit")
	}
	return
}

func (g *KMS) CreateKey(ctx context.Context) (*ecdsa.PublicKey, error) {
	client := g.client.Logical()

	if _, err := client.Write(fmt.Sprintf("/transit/keys/%s", g.keyPath), map[string]interface{}{
		"type": "ecdsa-p256",
	}); err != nil {
		return nil, errors.Wrap(err, "Failed to create transit key")
	}
	return g.ECDSAPublicKey(ctx)
}

func (g *KMS) ECDSAPublicKey(ctx context.Context) (*ecdsa.PublicKey, error) {
	k, err := g.publicKey(ctx)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok {
		if err != nil {
			return nil, errors.Errorf("public key was not ECDSA: %#v", k)
		}
	}
	return pub, nil
}

func (g *KMS) Public() crypto.PublicKey {
	key, err := g.pubKeyCache.Get("key")
	if err != nil {
		return nil
	}
	return key
}

func (g *KMS) publicKey(ctx context.Context) (crypto.PublicKey, error) {
	client := g.client.Logical()

	keyResult, err := client.Read(fmt.Sprintf("/transit/keys/%s", g.keyPath))
	if err != nil {
		return nil, errors.Wrap(err, "public key")
	}

	keysData, hasKeys := keyResult.Data["keys"]
	latestVersion, hasVersion := keyResult.Data["latest_version"]
	if !hasKeys || !hasVersion {
		return nil, errors.New("Failed to read transit key keys: corrupted response")
	}

	keys, ok := keysData.(map[string]interface{})
	if !ok {
		return nil, errors.New("Failed to read transit key keys: Invalid keys map")
	}

	keyVersion := latestVersion.(json.Number)
	keyData, ok := keys[string(keyVersion)]
	if !ok {
		return nil, errors.New("Failed to read transit key keys: corrupted response")
	}

	publicKeyPem, ok := keyData.(map[string]interface{})["public_key"]
	if !ok {
		return nil, errors.New("Failed to read transit key keys: corrupted response")
	}

	publicKeyData, _ := pem.Decode([]byte(publicKeyPem.(string)))
	if publicKeyData == nil {
		return nil, errors.New("pem.Decode failed")
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyData.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse public key")
	}
	return publicKey, nil
}

func (g *KMS) VerifySignature(payload, signature []byte) error {
	if err := g.VerifySignatureWithKey(g.Public(), payload, signature); err != nil {
		// key could have been rotated, clear cache and try again
		g.pubKeyCache.Remove(CacheKey)
		return g.VerifySignatureWithKey(g.Public(), payload, signature)
	}
	return nil
}
func (g *KMS) VerifySignatureWithKey(_ crypto.PublicKey, payload, signature []byte) error {
	client := g.client.Logical()
	encodedSig := base64.StdEncoding.EncodeToString(signature)

	signed := sha256.Sum256(payload)

	result, err := client.Write(fmt.Sprintf("/transit/verify/%s/%s", g.keyPath, hashAlg), map[string]interface{}{
		"input":     base64.StdEncoding.EncodeToString(signed[:]),
		"signature": fmt.Sprintf("%s%s", vaultV1DataPrefix, encodedSig),
	})

	if err != nil {
		return errors.Wrap(err, "verify")
	}

	valid, ok := result.Data["valid"]
	if !ok {
		return errors.New("corrupted response")
	}

	if isValid, ok := valid.(bool); ok && isValid {
		return errors.New("Failed vault verification")
	}
	return nil
}

// Vault likes to prefix base64 data with a version prefix
func vaultDecode(data interface{}) ([]byte, error) {
	encoded, ok := data.(string)
	if !ok {
		return nil, errors.New("Received non-string data")
	}
	return base64.StdEncoding.DecodeString(strings.TrimPrefix(encoded, vaultV1DataPrefix))
}
