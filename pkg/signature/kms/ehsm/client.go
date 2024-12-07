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

package ehsm

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/sigstore/sigstore/pkg/signature"
	sigkms "github.com/sigstore/sigstore/pkg/signature/kms"

	ehsm "github.com/intel/ehsm/sdk/go"
)

func init() {
	sigkms.AddProvider(ReferenceScheme, func(_ context.Context, keyResourceID string, hashFunc crypto.Hash, opts ...signature.RPCOption) (sigkms.SignerVerifier, error) {
		return LoadSignerVerifier(keyResourceID, hashFunc, opts...)
	})
}

type ehsmClient struct {
	client   *ehsm.Client
	keyPath  string
	keyCache *ttlcache.Cache[string, crypto.PublicKey]
}

var (
	errReference   = errors.New("kms specification should be in the format ehsm://<key>")
	referenceRegex = regexp.MustCompile(`^ehsm://(?P<path>\w(([\w-.]+)?\w)?)$`)
)

const (
	// use a consistent key for cache lookups
	cacheKey = "signer"

	// ReferenceScheme schemes for various KMS services are copied from https://github.com/google/go-cloud/tree/master/secrets
	ReferenceScheme = "ehsm://"
)

// ValidReference returns a non-nil error if the reference string is invalid
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
		err = fmt.Errorf("invalid ehsm format %q: %w", resourceID, err)
		return
	}
	keyPath = v[i]
	return
}

func newEhsmClient(keyResourceID string) (*ehsmClient, error) {
	if err := ValidReference(keyResourceID); err != nil {
		return nil, err
	}

	keyPath, err := parseReference(keyResourceID)
	if err != nil {
		return nil, err
	}

	client, err := ehsm.NewClient()
	if err != nil {
		return nil, err
	}

	ehsmClient := &ehsmClient{
		client:  client,
		keyPath: keyPath,
		keyCache: ttlcache.New[string, crypto.PublicKey](
			ttlcache.WithDisableTouchOnHit[string, crypto.PublicKey](),
		),
	}

	return ehsmClient, nil
}

func (e *ehsmClient) fetchPublicKey() (crypto.PublicKey, error) {
	KeyIDFileName := fmt.Sprintf("./%s", e.keyPath)
	keyid, err := ioutil.ReadFile(KeyIDFileName)
	if err != nil {
		return nil, err
	}

	return e.client.GetPublicKey(string(keyid))
}

func (e *ehsmClient) public() (crypto.PublicKey, error) {
	var lerr error
	loader := ttlcache.LoaderFunc[string, crypto.PublicKey](
		func(c *ttlcache.Cache[string, crypto.PublicKey], key string) *ttlcache.Item[string, crypto.PublicKey] {
			var pubkey crypto.PublicKey
			pubkey, lerr = e.fetchPublicKey()
			if lerr == nil {
				item := c.Set(key, pubkey, 300*time.Second)
				return item
			}
			return nil
		},
	)

	item := e.keyCache.Get(cacheKey, ttlcache.WithLoader[string, crypto.PublicKey](loader))
	return item.Value(), lerr
}

func (e *ehsmClient) sign(digest []byte, alg crypto.Hash, opts ...signature.SignOption) ([]byte, error) {
	encodedigest := base64.StdEncoding.EncodeToString(digest)
	KeyIDFileName := fmt.Sprintf("./%s", e.keyPath)
	keyid, err := ioutil.ReadFile(KeyIDFileName)
	if err != nil {
		return nil, err
	}

	signature, err := e.client.Sign(string(keyid), "EH_PAD_NONE", "EH_SHA_256", "EH_DIGEST", encodedigest)
	if err != nil {
		return nil, err
	}

	encodedSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, err
	}
	return []byte(encodedSignature), err
}

func (e ehsmClient) verify(sig, digest []byte, alg crypto.Hash, opts ...signature.VerifyOption) error {

	encodedSig := base64.StdEncoding.EncodeToString(sig)

	encodedigest := base64.StdEncoding.EncodeToString(digest)
	KeyIDFileName := fmt.Sprintf("./%s", e.keyPath)
	keyid, err := ioutil.ReadFile(KeyIDFileName)
	if err != nil {
		return err
	}
	result, err := e.client.Verify(string(keyid), "EH_PAD_NONE", "EH_SHA_256", "EH_DIGEST", encodedigest, encodedSig)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	if !result {
		return errors.New("failed ehsm verification")
	}

	return nil
}

func (e ehsmClient) createKey(keyspec string) (crypto.PublicKey, error) {
	key, err := e.client.CreateKey(keyspec, "EH_INTERNAL_KEY", "EH_KEYUSAGE_SIGN_VERIFY")
	if err != nil {
		return nil, err
	}

	keybyte := []byte(key)
	KeyIDFileName := fmt.Sprintf("./%s", e.keyPath)
	file, err := os.OpenFile(KeyIDFileName, os.O_CREATE|os.O_RDWR, 0600)
	defer file.Close()
	if err != nil {
		panic(err)
	}
	if keybyte != nil {
		file.Write(keybyte)
		fmt.Fprintln(os.Stderr, "KeyId written to", e.keyPath)
	}
	return e.public()
}
