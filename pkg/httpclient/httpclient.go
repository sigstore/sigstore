package httpclient

import (
	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/sigstore/sigstore/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/generated/client/operations"
	"github.com/sigstore/sigstore/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"net/url"
)

const defaultFulcioAddress = "https://fulcio.sigstore.dev"

func fulcioServer(addr string) string {
	if addr != "" {
		return addr
	}
	return defaultFulcioAddress
}

func GetCert(idToken *oauthflow.OIDCIDToken, proof []byte, pubBytes []uint8, addr string) (*operations.SigningCertCreated, error)  {
	fcli, err := getFulcioClient(fulcioServer(addr))
	if err != nil {
		return nil, err
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
		return nil, err
	}
	return resp, nil
}

func getFulcioClient(addr string) (*client.Fulcio, error) {
	url, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	rt := httptransport.New(url.Host, client.DefaultBasePath, []string{url.Scheme})
	rt.Consumers["application/pem-certificate-chain"] = runtime.TextConsumer()
	return client.New(rt, strfmt.Default), nil
}
