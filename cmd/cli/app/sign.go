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
package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/projectrekor/signer/config"
	"github.com/projectrekor/signer/pkg/x509pkg"
	"github.com/spf13/cobra"
)

const (
    CFSSLURLV1 = "http://127.0.0.1:8888/api/v1/cfssl/sign"
)

type Client struct {
    CFSSLURLV1    string
    HTTPClient *http.Client
}

// Cryptoresponse is exported, it models the data we receive.
type CSRRequest struct {
	CertificateRequest string  `json:"certificate_request"`
 }

 type responseMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

 type cfsslResponse struct {
	Success  bool                   `json:"success"`
	Result   map[string]interface{} `json:"result"`
	Errors   []responseMessage      `json:"errors"`
	Messages []responseMessage      `json:"messages"`
}

func userCFG() (string, error) {
	home, err := homedir.Dir()
	if err != nil {
		return "", err
	}
	userProfile := filepath.Join(home, ".signer")
	if _, err := os.Stat(userProfile); os.IsNotExist(err) {
		return userProfile, err
	}
	return userProfile, nil
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Generate Key Pair, CSR, sign and submit to sig t-log",
	Long: `Generates keys in memory, signs and artifact and then
	submits a manifest to the signature transparency.`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Generating key pair and cert signing request.")

		cfgDir, err := userCFG()
		if err != nil {
			log.Fatal(err)
		}

		config, err := config.LoadConfig(cfgDir)
		if err != nil {
			log.Fatal(err)
		}

		// Generate the private key
		privateKey, err := x509pkg.GenPrivKeyPEM()
		if err != nil {
			log.Fatal(err)
		}

		// Generate a CSR from our new key
		certPEM, err := x509pkg.GenerateCsr(config, privateKey)
		if err != nil {
			log.Fatal(err)
		}

		// Prepare CSR Json Payload for CFSSL signing
		jsonStr := string(certPEM)
		group := &CSRRequest{
			CertificateRequest:    jsonStr,
		}

		log.Println("Submitting csr to CA..")

		payloadBuf := new(bytes.Buffer)
		json.NewEncoder(payloadBuf).Encode(group)
		req, _ := http.NewRequest("POST", CFSSLURLV1, payloadBuf)

		client := &http.Client{}
		res, err := client.Do(req)
		if err != nil {
			fmt.Println(err)
		}

		defer res.Body.Close()

		log.Println("CFSSL response Status:", res.Status)
		bytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Fatalln(err)
		}
		var cfsslresp cfsslResponse
		err = json.Unmarshal(bytes, &cfsslresp)
		if err != nil {
			log.Fatal(err)
		}
		if cfsslresp.Success == true {
			log.Println("Certificate Successfully Generated")
		} else {
			log.Println("error:", cfsslresp.Errors)
		}

		// TODO sign artifact with key

		// TODO send manifest to rekor

		},
}

func init() {
	rootCmd.AddCommand(signCmd)
}
