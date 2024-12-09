package handler

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
)

func GetPluginArgs(osArgs []string) (*common.PluginArgs, error) {
	argsStr := osArgs[2]
	var args common.PluginArgs
	if err := json.Unmarshal([]byte(argsStr), &args); err != nil {
		return nil, err
	}
	return &args, nil
}

func WriteResponse(wr io.Writer, resp *common.PluginResp) error {
	enc, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	fmt.Fprint(wr, string(enc))
	return nil
}

func WriteErrorResponse(wr io.Writer, err error) error {
	resp := &common.PluginResp{
		ErrorMessage: err.Error(),
	}
	return WriteResponse(wr, resp)
}

func Dispatch(stdout io.Writer, stdin io.Reader, args *common.PluginArgs, impl kms.SignerVerifier) (*common.PluginResp, error) {
	var resp common.PluginResp
	var err error
	switch args.MethodName {
	case common.DefaultAlgorithmMethodName:
		resp.DefaultAlgorithm, err = DefaultAlgorithm(stdin, args.DefaultAlgorithm, impl)
	case common.SupportedAlgorithmsMethodName:
		resp.SupportedAlgorithms, err = SupportedAlgorithms(stdin, args.SuportedAlgorithms, impl)
	case common.PublicKeyMethodName:
		resp.PublicKey, err = PublicKey(stdin, args.PublicKey, impl)
	case common.CreateKeyMethodName:
		resp.CreateKey, err = CreateKey(stdin, args.CreateKey, impl)
	case common.SignMessageMethodName:
		resp.SignMessage, err = SignMessage(stdin, args.SignMessage, impl)
	}
	if err != nil {
		resp.ErrorMessage = err.Error()
	}
	WriteResponse(stdout, &resp)
	return &resp, err
}
