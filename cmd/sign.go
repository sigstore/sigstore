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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/sigstore/sigstore/pkg/generated/client/operations"
	"github.com/sigstore/sigstore/pkg/httpclients"
	"github.com/sigstore/sigstore/pkg/keymgmt"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"net/http"
	"os"
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
		fmt.Println("\nReceived OpenID Scope retrieved for account:", email)
		key, pub, err := keymgmt.GeneratePrivateKey("ecdsaP256")
		if err != nil {
			fmt.Println(err)
		}

		h := sha256.Sum256([]byte(email))
		proof, err := ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), h[:])
		if err != nil {
			fmt.Println(err)
		}
		// Send the token, signed proof and public key to fulcio for signing
		certResp, err := httpclients.GetCert(idToken, proof, pub, viper.GetString("fulcio-server"))
		if err != nil {
			switch t := err.(type) {
			case *operations.SigningCertDefault:
				if t.Code() == http.StatusInternalServerError {
					fmt.Println("Internal Server Error: ", err.Error())
				}
			default:
				fmt.Println("Something went wrong: ", err.Error())
			}
			os.Exit(1)
		}

		clientPEM, rootPEM := pem.Decode([]byte(certResp.Payload))
		certPEM := pem.EncodeToMemory(clientPEM)

		rootBlock, _ := pem.Decode([]byte(rootPEM))
		if rootBlock == nil {
			panic("failed to decode RootCA PEM")
		}

		certBlock, _ := pem.Decode([]byte(certPEM))
		if certBlock == nil {
			panic("failed to decode Client Certificate PEM")
		}

		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			panic("failed to parse certificate: " + err.Error())
		}
		fmt.Printf("Received signing Cerificate: %+v\n", cert.Subject)
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
		fmt.Println(err)
	}
}
