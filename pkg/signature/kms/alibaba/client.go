//
// Copyright 2024 The Sigstore Authors.
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

// Package alibaba implement the interface with alibaba cloud kms service
package alibaba

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	kms20160120 "github.com/alibabacloud-go/kms-20160120/v3/client"
	"github.com/alibabacloud-go/tea/tea"
	ttlcache "github.com/jellydator/ttlcache/v3"
	"github.com/sigstore/sigstore/pkg/signature"
	sigkms "github.com/sigstore/sigstore/pkg/signature/kms"
)

func init() {
	sigkms.AddProvider(ReferenceScheme, func(ctx context.Context, keyResourceID string, _ crypto.Hash, _ ...signature.RPCOption) (sigkms.SignerVerifier, error) {
		return LoadSignerVerifier(ctx, keyResourceID)
	})
}

const (
	cacheKey = "signer"
	// ReferenceScheme schemes for various KMS services
	ReferenceScheme = "alibabakms://"
)

type aliClient struct {
	client       *kms20160120.Client
	endpoint     string
	instanceId   string
	keyId        string
	keyVersionId string
	aliasName    string
	keyCache     *ttlcache.Cache[string, cmk]
}

var (
	errKMSReference = errors.New("kms specification should be in the format alibabakms://$ENDPOINT/[$INSTANCE_ID]/$KEY_ID/versions/$KEY_VERSION_ID")

	keyIDRE    = regexp.MustCompile(`^alibabakms://([^/\s]+)/([^/\s]+)?/([^/\s]+)/versions/([^/\s]+)$`)
	keyAliasRE = regexp.MustCompile(`^alibabakms://([^/\s]+)/([^/\s]+)?/alias/([^/\s]+)$`)
	allREs     = []*regexp.Regexp{keyIDRE, keyAliasRE}

	defaultProtocol = "https"
)

const (
	signingAlgorithmSpecECDSA_SHA_256 = "ECDSA_SHA_256"

	masterKeySpecEC_P256  = "EC_P256"
	masterKeySpecEC_P256K = "EC_P256K"

	defaultKeyUsage = "SIGN/VERIFY"
	defaultKeySpec  = masterKeySpecEC_P256
)

func newAliClient(ctx context.Context, keyResourceID string) (*aliClient, error) {
	if err := validReference(keyResourceID); err != nil {
		return nil, err
	}
	a := &aliClient{}
	var err error
	ref, err := parseReference(keyResourceID)
	if err != nil {
		return nil, err
	}
	a.endpoint = ref.endpoint
	a.instanceId = ref.instanceId
	a.keyId = ref.keyId
	a.keyVersionId = ref.keyVersionId
	a.aliasName = ref.aliasName

	if err := a.setupClient(ctx); err != nil {
		return nil, err
	}
	if a.keyId == "" && a.keyVersionId == "" {
		if err := a.fillKeyInfoViaAlias(ctx, a.aliasName); err != nil {
			return nil, err
		}
	}

	a.keyCache = ttlcache.New[string, cmk](
		ttlcache.WithDisableTouchOnHit[string, cmk](),
	)

	return a, nil
}

func (a *aliClient) setupClient(ctx context.Context) error {
	cred, err := getCredential()
	if err != nil {
		return err
	}
	config := &openapi.Config{
		Protocol:   tea.String(defaultProtocol),
		Endpoint:   tea.String(a.endpoint),
		Credential: cred,
	}

	client, err := kms20160120.NewClient(config)
	if err != nil {
		return err
	}
	a.client = client
	return nil
}

type keyMetadata struct {
	instanceId   string
	keySpec      string
	keyUsage     string
	keyId        string
	keyVersionId string
}

type cmk struct {
	KeyMetadata *keyMetadata
	PublicKey   crypto.PublicKey
}

func (c *cmk) HashFunc() crypto.Hash {
	return crypto.SHA256
}

func (c *cmk) Verifier() (signature.Verifier, error) {
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ecdsa")
	}
	return signature.LoadECDSAVerifier(pub, c.HashFunc())
}

func (a *aliClient) fetchCMK(ctx context.Context) (*cmk, error) {
	var err error
	cmk := &cmk{}
	cmk.PublicKey, err = a.fetchPublicKey(ctx)
	if err != nil {
		return nil, err
	}
	cmk.KeyMetadata, err = a.fetchKeyMeta(ctx)
	if err != nil {
		return nil, err
	}
	return cmk, nil
}

func (a *aliClient) getHashFunc(ctx context.Context) (crypto.Hash, error) {
	cmk, err := a.getCMK(ctx)
	if err != nil {
		return 0, err
	}
	return cmk.HashFunc(), nil
}

func (a *aliClient) getCMK(ctx context.Context) (*cmk, error) {
	var lerr error
	loader := ttlcache.LoaderFunc[string, cmk](
		func(c *ttlcache.Cache[string, cmk], key string) *ttlcache.Item[string, cmk] {
			var k *cmk
			k, lerr = a.fetchCMK(ctx)
			if lerr == nil {
				return c.Set(cacheKey, *k, time.Second*300)
			}
			return nil
		},
	)

	item := a.keyCache.Get(cacheKey, ttlcache.WithLoader[string, cmk](loader))
	if lerr == nil {
		cmk := item.Value()
		return &cmk, nil
	}
	return nil, lerr
}

func (a *aliClient) createKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	if a.keyId != "" && a.keyVersionId != "" {
		cmk, err := a.getCMK(ctx)
		if err != nil {
			return nil, err
		}
		return cmk.PublicKey, nil
	}

	description := "Created by Sigstore"
	req := &kms20160120.CreateKeyRequest{
		Description: tea.String(description),
		KeySpec:     tea.String(algorithm),
		KeyUsage:    tea.String(defaultKeyUsage),
	}
	if a.instanceId != "" {
		req.DKMSInstanceId = tea.String(a.instanceId)
	}
	resp, err := a.client.CreateKey(req)
	if err != nil {
		return nil, fmt.Errorf("creating key: %w", err)
	}
	if resp.Body == nil || resp.Body.KeyMetadata == nil {
		return nil, errors.New("response is nil")
	}

	a.keyId = tea.StringValue(resp.Body.KeyMetadata.KeyId)
	aliasName := a.aliasName
	_, err = a.client.CreateAlias(&kms20160120.CreateAliasRequest{
		AliasName: tea.String(aliasName),
		KeyId:     tea.String(a.keyId),
	})
	if err != nil {
		return nil, fmt.Errorf("creating alias %q: %w", aliasName, err)
	}
	if err := a.fillKeyInfoViaAlias(ctx, aliasName); err != nil {
		return nil, err
	}

	cmk, err := a.getCMK(ctx)
	if err != nil {
		return nil, fmt.Errorf("retrieving PublicKey from cache: %w", err)
	}

	return cmk.PublicKey, err
}

func (a *aliClient) fillKeyInfoViaAlias(ctx context.Context, aliasName string) error {
	keyId, err := a.getKeyIdViaAlias(ctx, aliasName)
	if err != nil {
		return err
	}
	versions, err := a.listKeyVersions(ctx, keyId)
	if err != nil {
		return err
	}
	if len(versions) == 0 {
		return errors.New("no key version found")
	}

	a.keyId = keyId
	a.keyVersionId = versions[0]
	return nil
}

func (a *aliClient) getKeyIdViaAlias(ctx context.Context, aliasName string) (string, error) {
	pageNumber := int32(1)
	pageSize := int32(100)
	req := &kms20160120.ListAliasesRequest{
		PageNumber: tea.Int32(pageNumber),
		PageSize:   tea.Int32(pageSize),
	}

loop:
	for {
		resp, err := a.client.ListAliases(req)
		if err != nil {
			return "", fmt.Errorf("list aliases: %w", err)
		}
		if resp.Body == nil {
			err = errors.New("response body is nil")
			return "", fmt.Errorf("list aliases: %w", err)
		}
		if len(resp.Body.Aliases.Alias) == 0 {
			break loop
		}
		for _, item := range resp.Body.Aliases.Alias {
			if tea.StringValue(item.AliasName) == aliasName {
				return tea.StringValue(item.KeyId), nil
			}
		}
		pageNumber++
		req.PageNumber = tea.Int32(pageNumber)
	}

	return "", fmt.Errorf("alias %s is not found", aliasName)
}

func (a *aliClient) listKeyVersions(ctx context.Context, keyId string) ([]string, error) {
	pageNumber := int32(1)
	pageSize := int32(100)
	req := &kms20160120.ListKeyVersionsRequest{
		PageNumber: tea.Int32(pageNumber),
		PageSize:   tea.Int32(pageSize),
		KeyId:      tea.String(keyId),
	}

	var versions []string
loop:
	for {
		resp, err := a.client.ListKeyVersions(req)
		if err != nil {
			return nil, fmt.Errorf("list key versions: %w", err)
		}
		if resp.Body == nil {
			err = errors.New("response body is nil")
			return nil, fmt.Errorf("list key version: %w", err)
		}
		if len(resp.Body.KeyVersions.KeyVersion) == 0 {
			break loop
		}
		for _, item := range resp.Body.KeyVersions.KeyVersion {
			versions = append(versions, tea.StringValue(item.KeyVersionId))
		}
		pageNumber++
		req.PageNumber = tea.Int32(pageNumber)
	}

	return versions, nil
}

func (a *aliClient) verify(ctx context.Context, sig, message io.Reader, opts ...signature.VerifyOption) error {
	cmk, err := a.getCMK(ctx)
	if err != nil {
		return err
	}
	verifier, err := cmk.Verifier()
	if err != nil {
		return err
	}
	return verifier.VerifySignature(sig, message, opts...)
}

func (a *aliClient) verifyRemotely(ctx context.Context, sig, digest []byte) error {
	alg := signingAlgorithmSpecECDSA_SHA_256
	req := &kms20160120.AsymmetricVerifyRequest{
		Algorithm:    tea.String(alg),
		Digest:       tea.String(base64.StdEncoding.EncodeToString(sig)),
		DryRun:       nil,
		KeyId:        tea.String(a.keyId),
		KeyVersionId: tea.String(a.keyVersionId),
		Value:        tea.String(base64.StdEncoding.EncodeToString(digest)),
	}

	_, err := a.client.AsymmetricVerify(req)

	if err != nil {
		return fmt.Errorf("unable to verify signature: %w", err)
	}
	return nil
}

func (a *aliClient) sign(ctx context.Context, digest []byte, _ crypto.Hash) ([]byte, error) {
	alg := signingAlgorithmSpecECDSA_SHA_256
	req := &kms20160120.AsymmetricSignRequest{
		Digest:       tea.String(base64.StdEncoding.EncodeToString(digest)),
		DryRun:       nil,
		KeyId:        tea.String(a.keyId),
		KeyVersionId: tea.String(a.keyVersionId),
		Algorithm:    tea.String(alg),
	}

	out, err := a.client.AsymmetricSign(req)

	if err != nil {
		return nil, fmt.Errorf("signing with kms: %w", err)
	}
	if out.Body == nil {
		err = errors.New("response body is nil")
		return nil, fmt.Errorf("signing with kms: %w", err)
	}
	decodedVal, err := base64.StdEncoding.DecodeString(tea.StringValue(out.Body.Value))
	if err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return decodedVal, nil
}

func (a *aliClient) fetchPublicKey(ctx context.Context) (crypto.PublicKey, error) {
	req := &kms20160120.GetPublicKeyRequest{
		DryRun:       nil,
		KeyId:        tea.String(a.keyId),
		KeyVersionId: tea.String(a.keyVersionId),
	}

	out, err := a.client.GetPublicKey(req)
	if err != nil {
		return nil, fmt.Errorf("getting public key: %w", err)
	}
	if out.Body == nil || out.Body.PublicKey == nil {
		return nil, fmt.Errorf("invalid response: %s", out.String())
	}

	block, _ := pem.Decode([]byte(tea.StringValue(out.Body.PublicKey)))
	if block == nil {
		return nil, fmt.Errorf("invalid public key: %s", tea.StringValue(out.Body.PublicKey))
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	return key, nil
}

func (a *aliClient) fetchKeyMeta(ctx context.Context) (*keyMetadata, error) {
	req := &kms20160120.DescribeKeyRequest{
		KeyId: tea.String(a.keyId),
	}
	resp, err := a.client.DescribeKey(req)
	if err != nil {
		return nil, fmt.Errorf("describing key: %w", err)
	}
	if resp.Body == nil || resp.Body.KeyMetadata == nil {
		return nil, fmt.Errorf("invalid response: %s", resp.String())
	}

	meta := &keyMetadata{
		instanceId:   tea.StringValue(resp.Body.KeyMetadata.DKMSInstanceId),
		keyId:        tea.StringValue(resp.Body.KeyMetadata.KeyId),
		keyVersionId: a.keyVersionId,
		keySpec:      tea.StringValue(resp.Body.KeyMetadata.KeySpec),
		keyUsage:     tea.StringValue(resp.Body.KeyMetadata.KeyUsage),
	}
	return meta, nil
}

type Reference struct {
	endpoint     string
	instanceId   string
	keyId        string
	keyVersionId string
	aliasName    string
}

// validReference returns a non-nil error if the reference string is invalid
func validReference(ref string) error {
	for _, re := range allREs {
		if re.MatchString(ref) {
			return nil
		}
	}
	return errKMSReference
}

// parseReference parses an alibabakms-scheme URI into its constituent parts.
func parseReference(resourceID string) (ref *Reference, err error) {
	var parts []string
	var tmpRef Reference

	for _, re := range allREs {
		parts = re.FindStringSubmatch(resourceID)
		if len(parts) == 5 {
			tmpRef.endpoint, tmpRef.instanceId = parts[1], parts[2]
			tmpRef.keyId = parts[3]
			tmpRef.keyVersionId = parts[4]
		} else if len(parts) == 4 {
			tmpRef.endpoint, tmpRef.instanceId = parts[1], parts[2]
			tmpRef.aliasName = "alias/" + parts[3]
		}
	}

	if err := tmpRef.validation(); err != nil {
		return nil, fmt.Errorf("invalid alibabakms format %q: %w", resourceID, err)
	}

	return &tmpRef, nil
}

func (r *Reference) validation() error {
	if r.endpoint == "" {
		return errors.New("endpoint is missing")
	}
	if r.aliasName == "" {
		if r.keyId == "" {
			return errors.New("keyId is missing")
		}
		if r.keyVersionId == "" {
			return errors.New("keyVersionId is missing")
		}
	}
	return nil
}
