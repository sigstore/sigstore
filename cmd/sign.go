/*
Copyright © 2021 Luke Hinds, Red Hat <lhinds@redhat.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"github.com/sigstore/sigstore/pkg/keymgmt"
	"os"
	"path/filepath"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
)

func userCFG() (string, error) {
	home, err := homedir.Dir()
	if err != nil {
		return "", err
	}
	userProfile := filepath.Join(home, ".sigstore")
	if _, err := os.Stat(userProfile); os.IsNotExist(err) {
		return userProfile, err
	}
	return userProfile, nil
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign and submit file to sigstore",
	Long: `Submit file to sigstore.`,
	Run: func(cmd *cobra.Command, args []string) {
		pub, key, err := keymgmt.GeneratePrivateKey("P384")
		if err != nil {
			fmt.Println(err)
		}
		// Just place holders, these will be removed once next PR is worked on
		fmt.Println(key)
		fmt.Println(pub)
		},
}

func init() {
	rootCmd.AddCommand(signCmd)
}
