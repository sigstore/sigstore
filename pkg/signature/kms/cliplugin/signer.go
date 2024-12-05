package cliplugin

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigkms "github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
)

var (
	ErrorExecutingPlugin         = errors.New("error executing plugin program")
	ErrorResponseParseError      = errors.New("parsing plugin response")
	ErrorPluginReturnError       = errors.New("plugin returned error")
	ErrorParsingPluginBinaryName = errors.New("parsing plugin binary name")
)

type PluginClient struct {
	sigkms.SignerVerifier
	Ctx             context.Context
	executable      string
	initOptions     common.InitOptions
	makeCommandFunc makeCommandFunc
}

func newPluginClient(ctx context.Context, executable string, initOptions *common.InitOptions, makeCommand makeCommandFunc) *PluginClient {
	pluginClient := &PluginClient{
		Ctx:             ctx,
		executable:      executable,
		initOptions:     *initOptions,
		makeCommandFunc: makeCommand,
	}
	return pluginClient
}

func (c PluginClient) invokePlugin(ctx context.Context, stdin io.Reader, args *common.PluginArgs) (*common.PluginResp, error) {
	args.InitOptions = &c.initOptions
	argsEnc, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	cmd := c.makeCommandFunc(ctx, stdin, os.Stderr, c.executable, common.ProtocolVersion, string(argsEnc))
	// we won't look at exit status as a pottential error.
	// If a program exit(1), the only debugging is to either parse the the returned error in stdout,
	// or for the user to examine the sterr logs.
	stdout, _ := cmd.Output()
	var resp common.PluginResp
	if unmarshallErr := json.Unmarshal(stdout, &resp); unmarshallErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrorResponseParseError, unmarshallErr)
	}
	if resp.ErrorMessage != "" {
		return nil, fmt.Errorf("%w: %s", ErrorPluginReturnError, resp.ErrorMessage)
	}
	return &resp, nil
}

func (c PluginClient) SupportedAlgorithms() (result []string) {
	args := &common.PluginArgs{
		Method:             common.SupportedAlgorithmsMethodName,
		SuportedAlgorithms: &common.SupportedAlgorithmsArgs{},
	}
	resp, err := c.invokePlugin(c.Ctx, nil, args)
	if err != nil {
		log.Fatal(err)
	}
	return resp.SupportedAlgorithms.SupportedAlgorithms
}

func (c PluginClient) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	ctx := c.Ctx
	keyVersion := "1"
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyKeyVersion(&keyVersion)
	}
	args := &common.PluginArgs{
		Method: common.PublicKeyMethodName,
		PublicKey: &common.PublicKeyArgs{
			KeyVersion: keyVersion,
		},
	}
	resp, err := c.invokePlugin(ctx, nil, args)
	if err != nil {
		return nil, err
	}
	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey(resp.PublicKey.PublicKeyPEM)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

func (c PluginClient) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	ctx := c.Ctx
	var signerOpts crypto.SignerOpts = c.initOptions.HashFunc
	var keyVersion string
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyCryptoSignerOpts(&signerOpts)
		opt.ApplyKeyVersion(&keyVersion)
	}
	args := &common.PluginArgs{
		Method: common.SignMessageMethodName,
		SignMessage: &common.SignMessageArgs{
			HashFunc:   signerOpts.HashFunc(),
			KeyVersion: keyVersion,
		},
	}
	resp, err := c.invokePlugin(ctx, message, args)
	if err != nil {
		return nil, err
	}
	signature := resp.SignMessage.Signature
	return signature, nil
}
