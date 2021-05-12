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

package httpclients

import (
	"net/url"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/sigstore/sigstore/pkg/generated/client"
	"github.com/sigstore/sigstore/pkg/generated/client/operations"
	"github.com/sigstore/sigstore/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/oauthflow"
)

const defaultFulcioAddress = "https://fulcio.sigstore.dev"

func fulcioServer(addr string) string {
	if addr != "" {
		return addr
	}
	return defaultFulcioAddress
}

func GetCert(idToken *oauthflow.OIDCIDToken, proof []byte, pubBytes []uint8, addr string) (*operations.SigningCertCreated, error) {
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
				Content: &content,
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
