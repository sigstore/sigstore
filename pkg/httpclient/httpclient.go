package httpclient

import (
	"encoding/pem"
	"fmt"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/spf13/viper"
	"github.com/sigstore/fulcio/pkg/generated/models"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/sigstore/fulcio/cmd/client/app"
	"github.com/sigstore/fulcio/pkg/oauthflow"
	"github.com/sigstore/fulcio/pkg/generated/client/operations"
)

const defaultFulcioAddress = "https://fulcio.sigstore.dev"

func fulcioServer() string {
	addr := viper.GetString("fulcio_address")
	fmt.Println("adddr:", addr)
	if addr != "" {
		return addr
	}
	return defaultFulcioAddress
}

func GetCert(idToken *oauthflow.OIDCIDToken, proof []byte, pubBytes []uint8) (string, string, error)  {
	fcli, err := app.GetFulcioClient(fulcioServer())
	if err != nil {
		return "", "", err
	}
	bearerAuth := httptransport.BearerToken(idToken.RawString)

	content := strfmt.Base64(pubBytes)
	email := strfmt.Base64(proof)
	params := operations.NewSigningCertParams()
	params.SetCertificateRequest(
		&models.CertificateRequest{
			PublicKey: &models.CertificateRequestPublicKey{
				Algorithm: swag.String(models.CertificateRequestPublicKeyAlgorithmEcdsa),
				Content:   &content,
			},
			SignedEmailAddress: &email,
		},
	)

	resp, err := fcli.Operations.SigningCert(params, bearerAuth)
	if err != nil {
		return "", "", err
	}

	// split the cert and the chain
	certBlock, chainPem := pem.Decode([]byte(resp.Payload))
	certPem := pem.EncodeToMemory(certBlock)
	return string(certPem), string(chainPem), nil

}