package alibaba

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func init() {
	os.Setenv("ALIBABA_CLOUD_ACCESS_KEY_ID", "foo")
	os.Setenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "bar")
	defaultProtocol = "http"
}

func TestSignerVerifier(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		action := r.Header.Get("X-Acs-Action")
		switch action {
		case "DescribeKey":
			w.Write([]byte(`{
"KeyMetadata": {

}
}`))
		case "GetPublicKey":
			w.Write([]byte(`{
"PublicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHlcsJdiAY8ax2AsQICBS7V1olnRx\nq2gW5Gnm96+8ti9+vyCuklSlqsZPe+Y+UgeJjm38pEU8klVGsHGz/aLt6w==\n-----END PUBLIC KEY-----"
}`))
		case "AsymmetricSign":
			w.Write([]byte(`{
"Value": "MEUCIQCfn8lM7gTViE6GoU3mGs5q7BW6AqwcmrREG0E27ed94QIgWN4pSAfWx9ao72w6FmLWBGImqf7uzFT8tZeGiG1/wFM="
}`))
		case "AsymmetricVerify":
			w.Write([]byte(`{}`))
		}
	}))
	defer s.Close()

	client, err := newAliClient(context.TODO(), resourceURIForTest)
	assert.NoError(t, err)
	client.client.Endpoint = tea.String(strings.Split(s.URL, "://")[1])
	client.client.Protocol = tea.String("http")

	sv := &SignerVerifier{
		client: client,
	}

	t.Run("PublicKey()", func(t *testing.T) {
		_, err = sv.PublicKey()
		assert.NoError(t, err)
	})

	t.Run("CreateKey()", func(t *testing.T) {
		_, err = sv.CreateKey(context.TODO(), defaultKeySpec)
		assert.NoError(t, err)
	})

	message := bytes.NewBuffer([]byte("test"))
	var sig []byte
	t.Run("SignMessage()", func(t *testing.T) {
		sig, err = sv.SignMessage(message)
		assert.NoError(t, err)
	})

	t.Log(sig)

	// local
	t.Run("VerifySignature() local", func(t *testing.T) {
		digest, _ := base64.StdEncoding.DecodeString("n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=")
		hashFunc, _ := sv.client.getHashFunc(context.TODO())
		err = sv.VerifySignature(bytes.NewBuffer(sig), message,
			options.WithCryptoSignerOpts(hashFunc),
			options.WithDigest(digest),
		)
		assert.NoError(t, err)
	})

	// local
	t.Run("VerifySignature() remote", func(t *testing.T) {
		err = sv.VerifySignature(bytes.NewBuffer(sig), message,
			options.WithRemoteVerification(true),
		)
		assert.NoError(t, err)
	})

	var sr crypto.Signer
	var opts crypto.SignerOpts
	t.Run("CryptoSigner()", func(t *testing.T) {
		sr, opts, err = sv.CryptoSigner(context.TODO(), func(err error) {
			t.Log(err)
		})
		assert.NoError(t, err)
	})

	t.Run("Signer.Public()", func(t *testing.T) {
		pc := sr.Public()
		assert.NotNil(t, pc)
	})

	t.Run("Signer.Sign()", func(t *testing.T) {
		digest, _ := base64.StdEncoding.DecodeString("n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=")
		sg, err := sr.Sign(nil, digest, opts)
		assert.NoError(t, err)
		assert.NotNil(t, sg)
	})
}

func TestSignerVerifier_CreateKey(t *testing.T) {
	var cListKeyVersions int
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		action := r.Header.Get("X-Acs-Action")
		switch action {
		case "ListAliases":
			w.Write([]byte(`
{
  "Aliases": {
    "Alias": [
      {
        "AliasName": "alias/foobar",
        "KeyId": "937483ef-22b7-4b23-foo-bar"
      }
    ]
  },
  "TotalCount": 1,
  "PageNumber": 1,
  "PageSize": 1
}
`))
		case "ListKeyVersions":
			cListKeyVersions++
			if cListKeyVersions < 2 {
				w.Write([]byte(`
{
  "KeyVersions": {
    "KeyVersion": [
      {
        "KeyId": "116e3af1-1ec7-43d3-964b-foobar",
        "KeyVersionId": "e1ddb403-5558-49f2-b34b-bar",
        "CreationDate": "2024-09-01T12:37:41Z"
      }
    ]
  },
  "TotalCount": 1,
  "PageNumber": 1,
  "PageSize": 20
}
`))
			} else {
				w.Write([]byte(`
{
  "KeyVersions": {
    "KeyVersion": []
  },
  "TotalCount": 1,
  "PageNumber": 2,
  "PageSize": 20
}
`))
			}
		case "DescribeKey":
			w.Write([]byte(`{
"KeyMetadata": {

}
}`))
		case "GetPublicKey":
			w.Write([]byte(`{
"PublicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHlcsJdiAY8ax2AsQICBS7V1olnRx\nq2gW5Gnm96+8ti9+vyCuklSlqsZPe+Y+UgeJjm38pEU8klVGsHGz/aLt6w==\n-----END PUBLIC KEY-----"
}`))
		}
	}))
	defer s.Close()

	entrypoint := strings.Split(s.URL, "://")[1]
	client, err := newAliClient(context.TODO(), fmt.Sprintf("alibabakms://%s//alias/foobar", entrypoint))
	assert.NoError(t, err)
	client.client.Endpoint = tea.String(entrypoint)
	client.client.Protocol = tea.String("http")

	sv := &SignerVerifier{
		client: client,
	}

	_, err = sv.CreateKey(context.TODO(), defaultKeySpec)
	assert.NoError(t, err)
}
