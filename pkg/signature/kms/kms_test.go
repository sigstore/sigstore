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

package kms_test

import (
	"testing"

	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/aws"
	"github.com/sigstore/sigstore/pkg/signature/kms/azure"
	"github.com/sigstore/sigstore/pkg/signature/kms/hashivault"

	"github.com/stretchr/testify/require"
)

func Test_SupportedProviders(t *testing.T) {
	supportedProviders := kms.SupportedProviders()
	require.Contains(t, supportedProviders, aws.ReferenceScheme)
	require.Contains(t, supportedProviders, azure.ReferenceScheme)
	require.NotContains(t, supportedProviders, "gcpkms://")
	require.Contains(t, supportedProviders, hashivault.ReferenceScheme)
}
