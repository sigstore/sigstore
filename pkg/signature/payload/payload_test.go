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

package payload

import (
	"encoding/json"
	"testing"

	"github.com/go-test/deep"
	"github.com/google/go-containerregistry/pkg/name"
)

const validDigest = "sha256:d34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33f"

func mustParseDigest(t *testing.T, digestStr string) name.Digest {
	t.Helper()
	digest, err := name.NewDigest(digestStr)
	if err != nil {
		t.Fatalf("could not parse digest %q: %v", digestStr, err)
	}
	return digest
}

func TestMarshalCosign(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		desc       string
		imgPayload Cosign
		expected   string
	}{
		{
			desc: "no claims",
			imgPayload: Cosign{
				Image: mustParseDigest(t, "example.com/test/image@"+validDigest),
			},
			expected: `{"critical":{"identity":{"docker-reference":"example.com/test/image"},"image":{"docker-manifest-digest":"sha256:d34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33f"},"type":"cosign container image signature"},"optional":null}`,
		},
		{
			desc: "standard atomic signature",
			imgPayload: Cosign{
				Image: mustParseDigest(t, "example.com/atomic/test/image@"+validDigest),
				Annotations: map[string]interface{}{
					"creator":   "atomic",
					"timestamp": 1458239713,
				},
			},
			expected: `{"critical":{"identity":{"docker-reference":"example.com/atomic/test/image"},"image":{"docker-manifest-digest":"sha256:d34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33f"},"type":"cosign container image signature"},"optional":{"creator":"atomic","timestamp":1458239713}}`,
		},
		{
			desc: "arbitrary claims",
			imgPayload: Cosign{
				Image: mustParseDigest(t, "example.com/cosign/test/image@"+validDigest),
				Annotations: map[string]interface{}{
					"creator": "anyone",
					"some_struct": map[string]interface{}{
						"foo":     "bar",
						"false":   true,
						"nothing": nil,
					},
					"CamelCase WithSpace": 8.314,
				},
			},
			expected: `{"critical":{"identity":{"docker-reference":"example.com/cosign/test/image"},"image":{"docker-manifest-digest":"sha256:d34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33f"},"type":"cosign container image signature"},"optional":{"CamelCase WithSpace":8.314,"creator":"anyone","some_struct":{"false":true,"foo":"bar","nothing":null}}}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			tc := tc
			t.Parallel()
			payload, err := json.Marshal(tc.imgPayload)
			if err != nil {
				t.Fatalf("json.Marshal returned error: %v", err)
			}

			if tc.expected != string(payload) {
				t.Errorf("marshaled payload was %q, wanted %q", string(payload), tc.expected)
			}
		})
	}
}

func TestUnmarshalCosign(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		desc    string
		payload string

		expected  Cosign
		expectErr bool
	}{
		{
			desc:    "no claims",
			payload: `{"critical":{"identity":{"docker-reference":"example.com/test/image"},"image":{"docker-manifest-digest":"sha256:d34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33f"},"type":"cosign container image signature"},"optional":null}`,
			expected: Cosign{
				Image: mustParseDigest(t, "example.com/test/image@"+validDigest),
			},
		},
		{
			desc:    "arbitrary claims",
			payload: `{"critical":{"identity":{"docker-reference":"example.com/cosign/test/image"},"image":{"docker-manifest-digest":"sha256:d34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33f"},"type":"cosign container image signature"},"optional":{"CamelCase WithSpace":8.314,"creator":"anyone","some_struct":{"false":true,"foo":"bar","nothing":null}}}`,
			expected: Cosign{
				Image: mustParseDigest(t, "example.com/cosign/test/image@"+validDigest),
				Annotations: map[string]interface{}{
					"creator": "anyone",
					"some_struct": map[string]interface{}{
						"foo":     "bar",
						"false":   true,
						"nothing": nil,
					},
					"CamelCase WithSpace": 8.314,
				},
			},
		},
		{
			desc:      "unknown type",
			payload:   `{"critical":{"identity":{"docker-reference":"example.com/atomic/test/image"},"image":{"docker-manifest-digest":"sha256:d34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33f"},"type":"atomic container signature"},"optional":{}}`,
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			tc := tc
			t.Parallel()
			var imgPayload Cosign
			err := json.Unmarshal([]byte(tc.payload), &imgPayload)
			if err != nil {
				if !tc.expectErr {
					t.Fatalf("json.Unmarshal unexpectedly returned an error: %v", err)
				}
				return // operation failed successfully
			}
			if tc.expectErr {
				t.Fatalf("json.Unmarshal returned %v, expected an error", imgPayload)
			}
			if diff := deep.Equal(tc.expected, imgPayload); diff != nil {
				t.Errorf("Cosign unmarshalled incorrectly: %v", diff)
			}
		})
	}
}
