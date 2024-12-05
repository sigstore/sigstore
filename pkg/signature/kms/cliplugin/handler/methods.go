package handler

import (
	"io"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func SupportedAlgorithms(stdin io.Reader, args *common.SupportedAlgorithmsArgs, impl kms.SignerVerifier) (*common.SupportedAlgorithmsResp, error) {
	supportedAlgorithms := impl.SupportedAlgorithms()
	resp := &common.SupportedAlgorithmsResp{
		SupportedAlgorithms: supportedAlgorithms,
	}
	return resp, nil
}

func PublicKey(stdin io.Reader, args *common.PublicKeyArgs, impl kms.SignerVerifier) (*common.PublicKeyResp, error) {
	opts := []signature.PublicKeyOption{
		options.WithKeyVersion(args.KeyVersion),
	}
	publicKey, err := impl.PublicKey(opts...)
	if err != nil {
		return nil, err
	}
	publicKeyPEM, err := cryptoutils.MarshalPublicKeyToPEM(publicKey)
	if err != nil {
		return nil, err
	}
	resp := &common.PublicKeyResp{
		PublicKeyPEM: publicKeyPEM,
	}
	return resp, nil
}

func SignMessage(stdin io.Reader, args *common.SignMessageArgs, impl kms.SignerVerifier) (*common.SignMessageResp, error) {
	opts := []signature.SignOption{
		options.WithKeyVersion(args.KeyVersion),
		options.WithCryptoSignerOpts(args.HashFunc),
	}
	signature, err := impl.SignMessage(stdin, opts...)
	if err != nil {
		return nil, err
	}
	resp := &common.SignMessageResp{
		Signature: signature,
	}
	return resp, nil
}
