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

package oauthflow

import (
	"context"
	"fmt"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
)

func TestProviderIsAzureBacked(t *testing.T) {

	actualAzureProviders := []string{
		"https://login.microsoftonline.com/6babcaad-604b-40ac-a9d7-9fd97c0b779f/v2.0",
	}

	notAzureProviders := []string{
		"https://accounts.google.com",
		"https://login.salesforce.com",
	}
	for _, tc := range actualAzureProviders {
		t.Run(fmt.Sprintf("testing azure provider %v", tc), func(t *testing.T) {
			p, err := oidc.NewProvider(context.Background(), tc)
			if err != nil {
				t.Error(err)
			}
			if !providerIsAzureBacked(p) {
				t.Errorf("valid azure provider URL %v was not detected as being azure backed", tc)
			}
		})
	}
	for _, tc := range notAzureProviders {
		t.Run(fmt.Sprintf("testing invalid azure provider %v", tc), func(t *testing.T) {
			p, err := oidc.NewProvider(context.Background(), tc)
			if err != nil {
				t.Error(err)
			}
			if providerIsAzureBacked(p) {
				t.Errorf("invalid azure provider URL %v was detected as being azure backed", tc)
			}
		})
	}
}
