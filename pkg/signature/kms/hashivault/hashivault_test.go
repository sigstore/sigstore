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
	"os"
	"path/filepath"
	"testing"
)

func TestNewHashivaultClient(t *testing.T) {
	tests := []struct {
		name                        string
		address                     string
		token                       string
		transitSecretEnginePath     string
		keyResourceID               string
		keyVersion                  uint64
		addressEnv                  string
		tokenEnv                    string
		vaultTokenFile              string
		tokenHelperScript           string
		wantErr                     bool
		wantAddress                 string
		wantToken                   string
		wantTransitSecretEnginePath string
	}{
		{
			name:                        "directly provided parameters",
			address:                     "https://vault.example.com",
			token:                       "hvc.exampletoken",
			transitSecretEnginePath:     "",
			keyResourceID:               "hashivault://test",
			keyVersion:                  1,
			wantErr:                     false,
			wantAddress:                 "https://vault.example.com",
			wantToken:                   "hvc.exampletoken",
			wantTransitSecretEnginePath: "transit",
		},
		{
			name:                        "environment variables",
			keyResourceID:               "hashivault://test",
			keyVersion:                  1,
			addressEnv:                  "https://vault.example.com",
			tokenEnv:                    "hvc.exampletoken",
			wantErr:                     false,
			wantAddress:                 "https://vault.example.com",
			wantToken:                   "hvc.exampletoken",
			wantTransitSecretEnginePath: "transit",
		},
		{
			name:                        "default token helper ~/.vault-token",
			address:                     "https://vault.example.com",
			keyResourceID:               "hashivault://test",
			keyVersion:                  1,
			vaultTokenFile:              "hvc.exampletoken",
			wantErr:                     false,
			wantAddress:                 "https://vault.example.com",
			wantToken:                   "hvc.exampletoken",
			wantTransitSecretEnginePath: "transit",
		},
		{
			name:          "custom token helper script",
			address:       "https://vault.example.com",
			keyResourceID: "hashivault://test",
			keyVersion:    1,
			tokenHelperScript: `#!/bin/bash
set -euo pipefail

cmd="${1}"

case "$cmd" in
get)
	# Print only the token to stdout
	echo -n "hvc.exampletoken"
	;;
store)
	# Read token from stdin (ignored)
	cat >/dev/null
	;;
erase)
	# Nothing to delete
	;;
*)
	echo "unknown command: $cmd" >&2
	exit 1
	;;
esac
			`,
			wantErr:                     false,
			wantAddress:                 "https://vault.example.com",
			wantToken:                   "hvc.exampletoken",
			wantTransitSecretEnginePath: "transit",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// backup environment variables
			oldAddressEnv := os.Getenv("VAULT_ADDR")
			oldTokenEnv := os.Getenv("VAULT_TOKEN")
			oldTransitSecretEnginePathEnv := os.Getenv("VAULT_TRANSIT_SECRET_ENGINE_PATH")
			os.Unsetenv("VAULT_ADDR")
			os.Unsetenv("VAULT_TOKEN")
			os.Unsetenv("VAULT_TRANSIT_SECRET_ENGINE_PATH")
			defer func() {
				os.Setenv("VAULT_ADDR", oldAddressEnv)
				os.Setenv("VAULT_TOKEN", oldTokenEnv)
				os.Setenv("VAULT_TRANSIT_SECRET_ENGINE_PATH", oldTransitSecretEnginePathEnv)
			}()

			// backup files
			homeDir, err := os.UserHomeDir()
			if err != nil {
				t.Fatalf("failed to get user home directory: %v", err)
			}
			oldVaultTokenFile, err := os.ReadFile(filepath.Join(homeDir, ".vault-token"))
			if err == nil {
				defer os.WriteFile(filepath.Join(homeDir, ".vault-token"), oldVaultTokenFile, 0o600)
			} else {
				defer os.Remove(filepath.Join(homeDir, ".vault-token"))
			}
			os.Remove(filepath.Join(homeDir, ".vault-token"))
			oldVaultConfigFile, err := os.ReadFile(filepath.Join(homeDir, ".vault"))
			if err == nil {
				defer os.WriteFile(filepath.Join(homeDir, ".vault"), oldVaultConfigFile, 0o600)
			} else {
				defer os.Remove(filepath.Join(homeDir, ".vault"))
			}
			os.Remove(filepath.Join(homeDir, ".vault"))

			// prepare environment variables and files
			if tt.addressEnv != "" {
				t.Setenv("VAULT_ADDR", tt.addressEnv)
			}
			if tt.tokenEnv != "" {
				t.Setenv("VAULT_TOKEN", tt.tokenEnv)
			}
			if tt.vaultTokenFile != "" {
				// write to ~/.vault-token
				err = os.WriteFile(filepath.Join(homeDir, ".vault-token"), []byte(tt.vaultTokenFile), 0o600)
				if err != nil {
					t.Fatalf("failed to write to ~/.vault-token: %v", err)
				}
			}
			if tt.tokenHelperScript != "" {
				// write "token_helper = \"<tmp-file-for-token-helper-script>\" to ~/.vault
				// write tt.tokenHelperScript to <tmp-file-for-token-helper-script>
				tmpFile, err := os.CreateTemp("", "token-helper.sh")
				if err != nil {
					t.Fatalf("failed to create temp file for token helper script: %v", err)
				}
				defer os.Remove(tmpFile.Name())
				_, err = tmpFile.WriteString(tt.tokenHelperScript)
				if err != nil {
					t.Fatalf("failed to write to temp file for token helper script: %v", err)
				}
				err = tmpFile.Chmod(0o700)
				if err != nil {
					t.Fatalf("failed to chmod temp file for token helper script: %v", err)
				}
				tmpFile.Close()

				// write to ~/.vault
				vaultConfigContent := []byte("token_helper = \"" + tmpFile.Name() + "\"\n")
				err = os.WriteFile(filepath.Join(homeDir, ".vault"), vaultConfigContent, 0o600)
				if err != nil {
					t.Fatalf("failed to write to ~/.vault: %v", err)
				}
			}

			// setup client
			client, err := newHashivaultClient(tt.address, tt.token, tt.transitSecretEnginePath, tt.keyResourceID, tt.keyVersion)

			// check results
			if (err != nil) != tt.wantErr {
				t.Errorf("newHashivaultClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if client.client.Address() != tt.wantAddress {
				t.Errorf("newHashivaultClient() got address = %v, want %v", client.client.Address(), tt.wantAddress)
			}
			token := client.client.Token()
			if token != tt.wantToken {
				t.Errorf("newHashivaultClient() got token = %v, want %v", token, tt.wantToken)
			}
			if client.transitSecretEnginePath != tt.wantTransitSecretEnginePath {
				t.Errorf("newHashivaultClient() got transitSecretEnginePath = %v, want %v", client.transitSecretEnginePath, tt.wantTransitSecretEnginePath)
			}
		})
	}
}

func TestParseReference(t *testing.T) {
	tests := []struct {
		in      string
		wantKey string
		wantErr bool
	}{
		{
			in:      "hashivault://cosign",
			wantKey: "cosign",
			wantErr: false,
		},
		{
			in:      "hashivault://cosign/nested",
			wantErr: true,
		},
		{
			in:      "foo://bar",
			wantErr: true,
		},
		{
			in:      "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			gotKey, err := parseReference(tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseReference() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotKey != tt.wantKey {
				t.Errorf("parseReference() gotKey = %v, want %v", gotKey, tt.wantKey)
			}
		})
	}
}
