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
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"

	sigpayload "github.com/sigstore/sigstore/pkg/signature/payload"
)

func SignImage(ctx context.Context, signer Signer, image name.Digest, optionalAnnotations map[string]interface{}) (payload, signature, prehashed []byte, err error) {
	imgPayload := sigpayload.Cosign{
		Image:       image,
		Annotations: optionalAnnotations,
	}
	payload, err = json.Marshal(imgPayload)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal payload to JSON: %v", err)
	}
	signature, prehashed, err = signer.Sign(ctx, payload)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to sign payload: %v", err)
	}
	return payload, signature, prehashed, nil
}

func VerifyImageSignature(ctx context.Context, verifier Verifier, payload, signature []byte) (image name.Digest, annotations map[string]interface{}, err error) {
	if err := verifier.Verify(ctx, payload, signature); err != nil {
		return name.Digest{}, nil, fmt.Errorf("signature verification failed: %v", err)
	}
	var imgPayload sigpayload.Cosign
	if err := json.Unmarshal(payload, &imgPayload); err != nil {
		return name.Digest{}, nil, fmt.Errorf("could not deserialize image payload: %v", err)
	}
	return imgPayload.Image, imgPayload.Annotations, nil
}
