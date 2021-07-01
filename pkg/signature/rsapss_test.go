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

package signature

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

const rsaKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDfCoj9PKxSIpOB
jVvP7B0l8Q6KXgwSxEBIobMl11nrH2Fv6ufZRWgma7E3rZcjRMygyfia6SB8KBjq
OBMHnxX78tp5IDxbPWniA7GGTWZyBsXgfLFH7GVGBh8fiJJtfL4TP/xmMzY47rx8
qvglkQDktdmSEmvfYmof5SIXD/CBI9YDxpXQB9EBcd16QnjwHUKHElOs4lZI9OeP
8TSV8tWyskq1cO4LxPS8WZVTvbq0jp84OwQTpWtJqG/DUQ1QfMjfixt+uauCDA87
iIwBC+rC7aCfaXHpqNayHzToUi2Jc34O6LMyfHgowEjQgnKehClY4Vuy0aJXQvKB
mRDqyjO/AgMBAAECggEBAIHOAs3Gis8+WjRSjXVjh882DG1QsJwXZQYgPT+vpiAl
YjKdNpOHRkbd9ARgXY5kEuccxDd7p7E6MM3XFpQf7M51ltpZfWboRgAIgD+WOiHw
eSbdytr95C6tj11twTJBH+naGk1sTokxv7aaVdKfIjL49oeBexBFmVe4pW9gkmrE
1z1y1a0RohqbZ0kprYPWjz5UhsNqbCzgkdDqS7IrcOwVg6zvKYFjHnqIHqaJXVif
FgIfoNt7tz+12FTHI+6OkKoN3YCJueaxneBhITXm6RLOpQWa9qhdUPbkJ9vQNfph
Qqke4faaxKY9UDma+GpEHR016AWufZp92pd9wQkDn0kCgYEA7w/ZizAkefHoZhZ8
Isn/fYu4fdtUaVgrnGUVZobiGxWrHRU9ikbAwR7UwbgRSfppGiJdAMq1lyH2irmb
4OHU64rjuYSlIqUWHLQHWmqUbLUvlDojH/vdmH/Zn0AbrLZaimC5UCjK3Eb7sAMq
G0tGeDX2JraQvx7KrbC6peTaaaMCgYEA7tgZBiRCQJ7+mNu+gX9x6OXtjsDCh516
vToRLkxWc7LAbC9LKsuEHl4e3vy1PY/nyuv12Ng2dBq4WDXozAmVgz0ok7rRlIFp
w8Yj8o/9KuGZkD/7tw/pLsVc9Q3Wf0ACrnAAh7+3dAvn3yg+WHwXzqWIbrseDPt9
ILCfUoNDpzUCgYAKFCX8y0PObFd67lm/cbq2xUw66iNN6ay1BEH5t5gSwkAbksis
ar03pyAbJrJ75vXFZ0t6fBFZ1NG7GYYr3fmHEKz3JlN7+W/MN/7TXgjx6FWgLy9J
6ul1w3YeU6qXBn0ctmU5ru6WiNuVmRyOWAcZjFTbXvkNRbQPzJKh6dsXdwKBgA1D
FIihxMf/zBVCxl48bF/JPJqbm3GaTfFp4wBWHsrH1yVqrtrOeCSTh1VMZOfpMK60
0W7b+pIR1cCYJbgGpDWoVLN3QSHk2bGUM/TJB/60jilTVC/DA2ikbtfwj8N7E2sK
Lw1amN4ptxNOEcAqC8xepqe3XiDMahNBm2cigMQtAoGBAKwrXvss2BKz+/6poJQU
A0c7jhMN8M9Y5S2Ockw07lrQeAgfu4q+/8ztm0NeHJbk01IJvJY5Nt7bSgwgNVlo
j7vR2BMAc9U73Ju9aeTl/L6GqmZyA+Ojhl5gA5DPZYqNiqi93ydgRaI6n4+o3dI7
5wnr40AmbuKCDvMOvN7nMybL
-----END PRIVATE KEY-----`

// Extracted from the certificate using:
// openssl x509 -pubkey -noout -in test.crt
const pubKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3wqI/TysUiKTgY1bz+wd
JfEOil4MEsRASKGzJddZ6x9hb+rn2UVoJmuxN62XI0TMoMn4mukgfCgY6jgTB58V
+/LaeSA8Wz1p4gOxhk1mcgbF4HyxR+xlRgYfH4iSbXy+Ez/8ZjM2OO68fKr4JZEA
5LXZkhJr32JqH+UiFw/wgSPWA8aV0AfRAXHdekJ48B1ChxJTrOJWSPTnj/E0lfLV
srJKtXDuC8T0vFmVU726tI6fODsEE6VrSahvw1ENUHzI34sbfrmrggwPO4iMAQvq
wu2gn2lx6ajWsh806FItiXN+DuizMnx4KMBI0IJynoQpWOFbstGiV0LygZkQ6soz
vwIDAQAB
-----END PUBLIC KEY-----`

func TestRSAPSSSignerVerifier(t *testing.T) {
	opts := &rsa.PSSOptions{
		Hash: crypto.SHA256,
	}

	privateKey, err := cryptoutils.UnmarshalPEMToPrivateKey([]byte(rsaKey), cryptoutils.SkipPassword)
	if err != nil {
		t.Errorf("unexpected error unmarshalling private key: %v", err)
	}
	sv, err := LoadRSAPSSSignerVerifier(privateKey.(*rsa.PrivateKey), crypto.SHA256, opts)
	if err != nil {
		t.Errorf("unexpected error creating signer/verifier: %v", err)
	}

	message := []byte("sign me")
	// created with openssl dgst -sign privKey.pem -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sha256
	sig, _ := base64.StdEncoding.DecodeString("UyouJxmgAKdm/Qfi9YA7aK71/eqyLcytmDN8CQqSCgcbGSln7S5fgIAmrwUfGp1tcxKjuNjLScn11+fqawiG9y66740VEC6GfS1hgElC2k3i/v8ly2mlt+4JYs3euzYxtWnxwQr4csc7Jy2V2cjoeQm6GTxkR4E6TRJM8/UxXvjKtp3rxRD8OuyfuGFkI0lU48vjKLgbuZKQqQdWuNUOnsPvtrHxvGRY/F1C0Ig3b7SoTyAjWSXQG42faKsFT+W1L/UdRK+m73TYdxMleI4uIGtl0k0Weui1/gK7Uh2FUP5+/F1ZoQRYk/DMz0M4QPmPsYLGwc8oduoF6JvNMGKymg==")
	testingSigner(t, sv, "rsa", crypto.SHA256, message)
	testingVerifier(t, sv, "rsa", crypto.SHA256, sig, message)

	// test with nil opts (sane defaults)
	sv, err = LoadRSAPSSSignerVerifier(privateKey.(*rsa.PrivateKey), crypto.SHA256, nil)
	if err != nil {
		t.Errorf("unexpected error creating signer/verifier: %v", err)
	}
	testingSigner(t, sv, "rsa", crypto.SHA256, message)
	testingVerifier(t, sv, "rsa", crypto.SHA256, sig, message)

	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(pubKey))
	if err != nil {
		t.Errorf("unexpected error unmarshalling public key: %v", err)
	}
	v, err := LoadRSAPSSVerifier(publicKey.(*rsa.PublicKey), crypto.SHA256, opts)
	if err != nil {
		t.Errorf("unexpected error creating verifier: %v", err)
	}
	testingVerifier(t, v, "rsa", crypto.SHA256, sig, message)

	v, err = LoadRSAPSSVerifier(publicKey.(*rsa.PublicKey), crypto.SHA256, nil)
	if err != nil {
		t.Errorf("unexpected error creating verifier with nil opts: %v", err)
	}
	testingVerifier(t, v, "rsa", crypto.SHA256, sig, message)
}
