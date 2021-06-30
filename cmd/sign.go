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

package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/generated/client/operations"
	"github.com/sigstore/sigstore/pkg/httpclients"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/tlog"
	"github.com/sigstore/sigstore/pkg/utils"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign and submit file to sigstore",
	Long:  `Submit file to sigstore.`,
	PreRun: func(cmd *cobra.Command, args []string) {
		// these are bound here so that they are not overwritten by other commands
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			fmt.Println("Error initializing cmd line args: ", err)
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		payload, err := ioutil.ReadFile(viper.GetString("artifact"))
		if err != nil {
			return err
		}

		mimetype, err := utils.GetFileType(viper.GetString("artifact"))
		if err != nil {
			return err
		}

		result := utils.FindString(mimetype)
		if !result {
			fmt.Println("File type currently not supported: ", mimetype)
			os.Exit(1)
		}

		// Retrieve idToken from oidc provider
		idToken, err := oauthflow.OIDConnect(
			viper.GetString("oidc-issuer"),
			viper.GetString("oidc-client-id"),
			viper.GetString("oidc-client-secret"),
			oauthflow.DefaultIDTokenGetter,
		)
		if err != nil {
			return err
		}
		fmt.Println("\nReceived OpenID Scope retrieved for account:", idToken.Subject)

		signer, _, err := signature.NewDefaultECDSASignerVerifier()
		if err != nil {
			return err
		}

		pub, err := signer.PublicKey()
		if err != nil {
			return err
		}
		pubBytes, err := cryptoutils.MarshalPublicKeyToDER(pub)
		if err != nil {
			return err
		}

		proof, err := signer.SignMessage(bytes.NewReader([]byte(idToken.Subject)))
		if err != nil {
			return err
		}

		certResp, err := httpclients.GetCert(idToken, proof, pubBytes, viper.GetString("fulcio-server"))
		if err != nil {
			switch t := err.(type) {
			case *operations.SigningCertDefault:
				if t.Code() == http.StatusInternalServerError {
					return err
				}
			default:
				return err
			}
			os.Exit(1)
		}

		certs, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(certResp.Payload))
		if err != nil {
			return err
		} else if len(certs) == 0 {
			return errors.New("no certificates were found in response")
		}
		signingCert := certs[0]
		signingCertPEM, err := cryptoutils.MarshalCertificateToPEM(signingCert)
		if err != nil {
			return err
		}

		fmt.Println("Received signing cerificate with serial number: ", signingCert.SerialNumber)

		fmt.Printf("Received signing Cerificate: %+v\n", signingCert.Subject)

		signature, err := signer.SignMessage(bytes.NewReader(payload))
		if err != nil {
			panic(fmt.Sprintf("Error occurred while during artifact signing: %s", err))
		}

		// Send to rekor
		fmt.Println("Sending entry to transparency log")
		tlogEntry, err := tlog.UploadToRekor(
			signingCertPEM,
			signature,
			viper.GetString("rekor-server"),
			payload,
		)
		if err != nil {
			return err
		}
		fmt.Println("Rekor entry successful. URL: ", tlogEntry)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(signCmd)
	signCmd.PersistentFlags().String("oidc-issuer", "https://oauth2.sigstore.dev/auth", "OIDC provider to be used to issue ID token")
	signCmd.PersistentFlags().String("oidc-client-id", "sigstore", "client ID for application")
	signCmd.PersistentFlags().String("oidc-client-secret", "", "client secret for application")
	signCmd.PersistentFlags().StringP("output", "o", "-", "output file to write certificate chain to")
	signCmd.PersistentFlags().StringP("artifact", "a", "", "artifact to sign")
	if err := viper.BindPFlags(signCmd.PersistentFlags()); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
