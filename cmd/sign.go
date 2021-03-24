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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/httpclient"
	"github.com/sigstore/sigstore/pkg/keymgmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign and submit file to sigstore",
	Long: `Submit file to sigstore.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Retrieve idToken from oidc provider
		idToken, email, err := oauthflow.OIDConnect(
			viper.GetString("oidc-issuer"),
			viper.GetString("oidc-client-id"),
			viper.GetString("oidc-client-secret"))
		if err != nil {
			fmt.Println(err)
		}
		// create 'keyless'
		// The following algorithms are available:
		// ecdsaP224, ecdsaP256, ecdsaP384, ecdsaP521
		key, pub, err := keymgmt.GeneratePrivateKey("ecdsaP256")
		if err != nil {
			fmt.Println(err)
		}

		// Sign the email address as part of the request
		h := sha256.Sum256([]byte(email))
		proof, err := ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), h[:])
		if err != nil {
			fmt.Println(err)
		}
		// Send the token, signed proof and public key to fulcio for signing
		block, pem, err := httpclient.GetCert((*oauthflow.OIDCIDToken)(idToken), proof, pub, viper.GetString("fulcio-server"))
		if err != nil {
			fmt.Println(err)
		}
		// TODO: implement output for certs
		fmt.Println(block)
		fmt.Println(pem)
		},
}

func init() {
	rootCmd.AddCommand(signCmd)
	signCmd.PersistentFlags().String("oidc-issuer", "https://accounts.google.com", "OIDC provider to be used to issue ID token")
	signCmd.PersistentFlags().String("oidc-client-id", "237800849078-rmntmr1b2tcu20kpid66q5dbh1vdt7aj.apps.googleusercontent.com", "client ID for application")
	// THIS IS NOT A SECRET - IT IS USED IN THE NATIVE/DESKTOP FLOW.
	signCmd.PersistentFlags().String("oidc-client-secret", "CkkuDoCgE2D_CCRRMyF_UIhS", "client secret for application")
	signCmd.PersistentFlags().StringP("output", "o", "-", "output file to write certificate chain to")
	if err := viper.BindPFlags(signCmd.PersistentFlags()); err != nil {
		log.Println(err)
	}
}
