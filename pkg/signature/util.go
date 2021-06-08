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
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/google/go-containerregistry/pkg/name"

	sigpayload "github.com/sigstore/sigstore/pkg/signature/payload"
)

func SignImage(signer Signer, image name.Digest, optionalAnnotations map[string]interface{}, opts ...SignOption) (payload, signature []byte, err error) {
	imgPayload := sigpayload.Cosign{
		Image:       image,
		Annotations: optionalAnnotations,
	}
	payload, err = json.Marshal(imgPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal payload to JSON: %v", err)
	}
	signature, err = signer.Sign(bytes.NewReader(payload), opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign payload: %v", err)
	}
	return payload, signature, nil
}

func VerifyImageSignature(verifier Verifier, payload, signature []byte, opts ...VerifyOption) (image name.Digest, annotations map[string]interface{}, err error) {
	if err := verifier.Verify(bytes.NewReader(payload), signature, opts...); err != nil {
		return name.Digest{}, nil, fmt.Errorf("signature verification failed: %v", err)
	}
	var imgPayload sigpayload.Cosign
	if err := json.Unmarshal(payload, &imgPayload); err != nil {
		return name.Digest{}, nil, fmt.Errorf("could not deserialize image payload: %v", err)
	}
	return imgPayload.Image, imgPayload.Annotations, nil
}

func isSupportedAlg(alg crypto.Hash, supportedAlgs []crypto.Hash) bool {
	if supportedAlgs == nil {
		return true
	}
	for _, supportedAlg := range supportedAlgs {
		if alg == supportedAlg {
			return true
		}
	}
	return false
}

func MessageToVerify(rawMessage io.Reader, defaultHashAlg crypto.Hash, supportedHashAlgs []crypto.Hash, opts ...VerifyOption) (messageToVerify []byte, hashedWith crypto.Hash, err error) {
	var cryptoOpts crypto.SignerOpts = defaultHashAlg
	for _, opt := range opts {
		opt.ApplyDigest(&messageToVerify)
		opt.ApplyCryptoSignerOpts(&cryptoOpts)
	}
	hashedWith = cryptoOpts.HashFunc()
	if !isSupportedAlg(hashedWith, supportedHashAlgs) {
		return nil, crypto.Hash(0), fmt.Errorf("unsupported hash algorithm: %q not in %v", hashedWith.String(), supportedHashAlgs)
	}
	if len(messageToVerify) > 0 {
		return messageToVerify, hashedWith, nil
	}
	hash, err := HashedMessage(rawMessage, hashedWith)
	return hash, hashedWith, err
}

func MessageToSign(rawMessage io.Reader, defaultHashAlg crypto.Hash, supportedHashAlgs []crypto.Hash, opts ...SignOption) (messageToSign []byte, hashedWith crypto.Hash, err error) {
	var cryptoOpts crypto.SignerOpts = defaultHashAlg
	for _, opt := range opts {
		opt.ApplyDigest(&messageToSign)
		opt.ApplyCryptoSignerOpts(&cryptoOpts)
	}
	hashedWith = cryptoOpts.HashFunc()
	if !isSupportedAlg(hashedWith, supportedHashAlgs) {
		return nil, crypto.Hash(0), fmt.Errorf("unsupported hash algorithm: %q not in %v", hashedWith.String(), supportedHashAlgs)
	}
	if len(messageToSign) > 0 {
		return messageToSign, hashedWith, nil
	}
	hash, err := HashedMessage(rawMessage, hashedWith)
	return hash, hashedWith, err
}

func HashedMessage(rawMessage io.Reader, hashAlg crypto.Hash) (messageToSign []byte, err error) {
	rawPayload, err := ioutil.ReadAll(rawMessage)
	if err != nil {
		return nil, err
	}
	if hashAlg == crypto.Hash(0) {
		return rawPayload, nil
	}
	h := hashAlg.New()
	if _, err := h.Write(rawPayload); err != nil {
		return nil, fmt.Errorf("failed to create hash: %v", err)
	}
	return h.Sum(nil), nil
}

func GetRand(defaultRandReader io.Reader, opts ...SignOption) io.Reader {
	randReader := defaultRandReader
	for _, opt := range opts {
		opt.ApplyRand(&randReader)
	}
	return randReader
}
