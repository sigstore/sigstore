package handler

import (
	"context"
	"io"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func DefaultAlgorithm(stdin io.Reader, args *common.DefaultAlgorithmArgs, impl kms.SignerVerifier) (*common.DefaultAlgorithmResp, error) {
	defaultAlgorithm := impl.DefaultAlgorithm()
	resp := &common.DefaultAlgorithmResp{
		DefaultAlgorithm: defaultAlgorithm,
	}
	return resp, nil
}

func SupportedAlgorithms(stdin io.Reader, args *common.SupportedAlgorithmsArgs, impl kms.SignerVerifier) (*common.SupportedAlgorithmsResp, error) {
	supportedAlgorithms := impl.SupportedAlgorithms()
	resp := &common.SupportedAlgorithmsResp{
		SupportedAlgorithms: supportedAlgorithms,
	}
	return resp, nil
}

func getRPCOpts(args *common.RPCOption) []signature.RPCOption {
	opts := []signature.RPCOption{}
	if args.CtxDeadline != nil {
		ctx, cancel := context.WithDeadline(context.TODO(), *args.CtxDeadline)
		defer cancel()
		opts = append(opts, options.WithContext(ctx))
	}
	if args.KeyVersion != nil {
		opts = append(opts, options.WithKeyVersion(*args.KeyVersion))
	}
	if args.RPCAuth != nil {
		opts = append(opts, options.WithRPCAuthOpts(*args.RPCAuth))
	}
	if args.RemoteVerification != nil {
		opts = append(opts, options.WithRemoteVerification(*args.RemoteVerification))
	}
	return opts
}

func PublicKey(stdin io.Reader, args *common.PublicKeyArgs, impl kms.SignerVerifier) (*common.PublicKeyResp, error) {
	opts := []signature.PublicKeyOption{}
	for _, opt := range getRPCOpts(args.PublicKeyOptions.RPCOption) {
		opts = append(opts, opt)
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

func CreateKey(stdin io.Reader, args *common.CreateKeyArgs, impl kms.SignerVerifier) (*common.CreateKeyResp, error) {
	ctx := context.TODO()
	if args.CtxDeadline != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, *args.CtxDeadline)
		defer cancel()
	}
	publicKey, err := impl.CreateKey(ctx, args.Algorithm)
	if err != nil {
		return nil, err
	}
	publicKeyPEM, err := cryptoutils.MarshalPublicKeyToPEM(publicKey)
	if err != nil {
		return nil, err
	}
	resp := &common.CreateKeyResp{
		PublicKeyPEM: publicKeyPEM,
	}
	return resp, nil
}

func getMessageOptions(args *common.MessageOption) []signature.MessageOption {
	opts := []signature.MessageOption{}
	if args.Digest != nil {
		opts = append(opts, options.WithDigest(*args.Digest))
	}
	if args.HashFunc != nil {
		opts = append(opts, options.WithCryptoSignerOpts(*args.HashFunc))
	}
	return opts
}

func SignMessage(stdin io.Reader, args *common.SignMessageArgs, impl kms.SignerVerifier) (*common.SignMessageResp, error) {
	opts := []signature.SignOption{}
	for _, opt := range getRPCOpts(args.SignOptions.RPCOption) {
		opts = append(opts, opt.(signature.SignOption))
	}
	for _, opt := range getMessageOptions(args.SignOptions.MessageOption) {
		opts = append(opts, opt.(signature.SignOption))
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
