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
	"github.com/pkg/browser"
	"github.com/sigstore/sigstore/config"
	"github.com/sigstore/sigstore/pkg/x509pkg"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	googleOauthConfig *oauth2.Config
	oauthStateString = "you-need-to-replace-me-with-rand"
)

const (
    CFSSLURLV1 = "http://127.0.0.1:8888/api/v1/cfssl/sign"
	WEBPKI = "http://127.0.0.1:8889/api/v1/submitcsr"
)

type Client struct {
    CFSSLURLV1    string
    HTTPClient *http.Client
}

type Userinfo struct {
    Id string `json:"id"`
    Email  string `json:"email"`
	VerifiedEmail bool `json:"verified_email"`
	Picture string `json:"picture"`

}

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
	userProfile := filepath.Join(home, ".sigstore")
	if _, err := os.Stat(userProfile); os.IsNotExist(err) {
		return userProfile, err
	}
	return userProfile, nil
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	content, err := getUserInfo(r.FormValue("state"), r.FormValue("code"))
	if err != nil {
		fmt.Println(err.Error())
	}

	var userinfo Userinfo
	err = json.Unmarshal(content, &userinfo)
	if err != nil {
		fmt.Println(err)
	}
	log.Println("Google Identity: ", userinfo.Id)
	log.Println("Google Service Email: ", userinfo.Email)
	log.Println("Google Email Verified: ", userinfo.VerifiedEmail)

	cfgDir, err := userCFG()
		if err != nil {
			log.Fatal(err)
		}

	config, err := config.LoadConfig(cfgDir)
	if err != nil {
		log.Fatal(err)
	}
    log.Println("Encoding Private Key pair to memory")
	// Generate the private key
	privateKey, err := x509pkg.GenPrivKeyPEM()
	if err != nil {
		log.Fatal(err)
	}

	// Generate a CSR from our new key
	log.Println("Generating Certificate Signing Request")
	certPEM, err := x509pkg.GenerateCsr(userinfo.Email, config, privateKey)
	if err != nil {
		log.Fatal(err)
	}

	// Prepare CSR Json Payload for CFSSL signing
	jsonStr := string(certPEM)
	group := &CSRRequest{
		CertificateRequest:    jsonStr,
	}
	log.Println("Submitting Certificate Signing Request")
	payloadBuf := new(bytes.Buffer)
	json.NewEncoder(payloadBuf).Encode(group)
	req, _ := http.NewRequest("POST", WEBPKI, payloadBuf)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}

	defer res.Body.Close()

	log.Println("WebPKI response Status:", res.Status)
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
	log.Println("Signing Artifact")
	log.Println("Flushing Keys")
}

func getUserInfo(state string, code string) ([]byte, error) {
	if state != oauthStateString {
		return nil, fmt.Errorf("invalid oauth state")
	}

	token, err := googleOauthConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %s", err.Error())
	}

	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}

	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading response body: %s", err.Error())
	}

	return contents, nil
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Generate Key Pair, CSR, sign and submit to sig t-log",
	Long: `Generates keys in memory, signs and artifact and then
	submits a manifest to the signature transparency.`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Open Browser for Google Auth.")
		url := googleOauthConfig.AuthCodeURL(oauthStateString)
		browser.OpenURL(url)
		http.HandleFunc("/callback", handleGoogleCallback)
		http.ListenAndServe(":8080", nil)

		},
}

func init() {
	rootCmd.AddCommand(signCmd)
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/callback",
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}
}
