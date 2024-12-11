package handler

import (
	"io"

	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
)

// TODO: Additonal methods to be implemented

func SupportedAlgorithms(stdin io.Reader, args *common.SupportedAlgorithmsArgs, impl kms.SignerVerifier) (*common.SupportedAlgorithmsResp, error) {
	supportedAlgorithms := impl.SupportedAlgorithms()
	resp := &common.SupportedAlgorithmsResp{
		SupportedAlgorithms: supportedAlgorithms,
	}
	return resp, nil
}

// TODO: use extracted values from signature.RPCOption, signature.SignOption, and signature.PublikKeyOption.

// SignMessage signs the message.
func SignMessage(stdin io.Reader, args *common.SignMessageArgs, impl kms.SignerVerifier) (*common.SignMessageResp, error) {
	signature, err := impl.SignMessage(stdin)
	if err != nil {
		return nil, err
	}
	resp := &common.SignMessageResp{
		Signature: signature,
	}
	return resp, nil
}
