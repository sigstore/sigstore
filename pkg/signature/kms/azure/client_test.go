//
// Copyright 2022 The Sigstore Authors.
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

package azure

import (
	"os"
	"testing"
)

func TestGetAuthenticationMethod(t *testing.T) {
	clearEnv := map[string]string{
		"AZURE_TENANT_ID":     "",
		"AZURE_CLIENT_ID":     "",
		"AZURE_CLIENT_SECRET": "",
		"AZURE_AUTH_METHOD":   "",
	}
	resetEnv := testSetEnv(t, clearEnv)
	defer resetEnv()

	cases := []struct {
		testDescription      string
		environmentVariables map[string]string
		expectedResult       authenticationMethod
	}{
		{
			testDescription:      "No environment variables set",
			environmentVariables: map[string]string{},
			expectedResult:       unknownAuthenticationMethod,
		},
		{
			testDescription: "AZURE_AUTH_METHOD=environment",
			environmentVariables: map[string]string{
				"AZURE_AUTH_METHOD": "environment",
			},
			expectedResult: environmentAuthenticationMethod,
		},
		{
			testDescription: "AZURE_AUTH_METHOD=cli",
			environmentVariables: map[string]string{
				"AZURE_AUTH_METHOD": "cli",
			},
			expectedResult: cliAuthenticationMethod,
		},
		{
			testDescription: "Set environment variables AZURE_TENANT_ID, AZURE_CLIENT_ID & AZURE_CLIENT_SECRET",
			environmentVariables: map[string]string{
				"AZURE_TENANT_ID":     "foo",
				"AZURE_CLIENT_ID":     "bar",
				"AZURE_CLIENT_SECRET": "baz",
			},
			expectedResult: environmentAuthenticationMethod,
		},
	}

	for i, c := range cases {
		t.Logf("Test #%d: %s", i, c.testDescription)
		reset := testSetEnv(t, c.environmentVariables)

		result := getAuthenticationMethod()
		if result != c.expectedResult {
			t.Logf("got: %q, want: %q", result, c.expectedResult)
			t.Fail()
		}

		reset()
	}
}

func testSetEnv(t *testing.T, s map[string]string) func() {
	t.Helper()

	backup := map[string]string{}
	for k, v := range s {
		currentEnv := os.Getenv(k)
		backup[k] = currentEnv
		if v == "" {
			os.Unsetenv(k)
			continue
		}
		os.Setenv(k, v)
	}

	return func() {
		for k, v := range backup {
			if v == "" {
				os.Unsetenv(k)
				continue
			}
			os.Setenv(k, v)
		}
	}
}
