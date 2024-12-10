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
	"time"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

var (
	ErrorExecutingPlugin         = errors.New("error executing plugin program")
	ErrorResponseParseError      = errors.New("parsing plugin response")
	ErrorPluginReturnError       = errors.New("plugin returned error")
	ErrorParsingPluginBinaryName = errors.New("parsing plugin binary name")
	ErrorUnsupportedMethod       = errors.New("unsupported methodArgs")
)

type PluginClient struct {
	kms.SignerVerifier
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

// invokePlugin invokes the plugin program and parses its response.
func (c PluginClient) invokePlugin(ctx context.Context, stdin io.Reader, methodArgs *common.MethodArgs) (*common.PluginResp, error) {
	pluginArgs := &common.PluginArgs{
		InitOptions: &c.initOptions,
		MethodArgs:  methodArgs,
	}
	argsEnc, err := json.Marshal(pluginArgs)
	if err != nil {
		return nil, err
	}
	cmd := c.makeCommandFunc(ctx, stdin, os.Stderr, c.executable, common.ProtocolVersion, string(argsEnc))
	// We won't look at the program's non-zero exit code, but we will respect any other
	// error, and cases when exec.ExitError.ExitCode() is 0 or -1:
	//   * (0) the program finished successfuly or
	//   * (-1) there was some other problem not due to the program itself.
	// The only debugging is to either parse the the returned error in stdout,
	// or for the user to examine the sterr logs.
	// See https://pkg.go.dev/os#ProcessState.ExitCode.
	stdout, err := cmd.Output()
	var exitError commandExitError
	if err != nil && (!errors.As(err, &exitError) || exitError.ExitCode() < 1) {
		return nil, fmt.Errorf("%w: %w", ErrorExecutingPlugin, err)
	}
	var resp common.PluginResp
	if unmarshallErr := json.Unmarshal(stdout, &resp); unmarshallErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrorResponseParseError, unmarshallErr)
	}
	if resp.ErrorMessage != "" {
		return nil, fmt.Errorf("%w: %s", ErrorPluginReturnError, resp.ErrorMessage)
	}
	return &resp, nil
}

func (c PluginClient) DefaultAlgorithm() string {
	args := &common.MethodArgs{
		MethodName:       common.DefaultAlgorithmMethodName,
		DefaultAlgorithm: &common.DefaultAlgorithmArgs{},
	}
	resp, err := c.invokePlugin(context.TODO(), nil, args)
	if err != nil {
		log.Fatal(err)
	}
	return resp.DefaultAlgorithm.DefaultAlgorithm
}

func (c PluginClient) SupportedAlgorithms() (result []string) {
	args := &common.MethodArgs{
		MethodName:          common.SupportedAlgorithmsMethodName,
		SupportedAlgorithms: &common.SupportedAlgorithmsArgs{},
	}
	resp, err := c.invokePlugin(context.TODO(), nil, args)
	if err != nil {
		log.Fatal(err)
	}
	return resp.SupportedAlgorithms.SupportedAlgorithms
}

func (c PluginClient) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	rpcOpts := []signature.RPCOption{}
	for _, opt := range opts {
		rpcOpts = append(rpcOpts, opt)
	}
	args := &common.MethodArgs{
		MethodName: common.PublicKeyMethodName,
		PublicKey: &common.PublicKeyArgs{
			PublicKeyOptions: &common.PublicKeyOptions{
				RPCOptions: getRPCOptions(rpcOpts),
			},
		},
	}
	ctx := c.Ctx
	if args.PublicKey.PublicKeyOptions.CtxDeadline != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, *args.PublicKey.PublicKeyOptions.CtxDeadline)
		defer cancel()
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

func (c PluginClient) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	args := &common.MethodArgs{
		MethodName: common.CreateKeyMethodName,
		CreateKey: &common.CreateKeyArgs{
			Algorithm: algorithm,
		},
	}
	resp, err := c.invokePlugin(context.TODO(), nil, args)
	if err != nil {
		return nil, err
	}
	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey(resp.CreateKey.PublicKeyPEM)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

func (c PluginClient) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	rpcOpts := []signature.RPCOption{}
	for _, opt := range opts {
		rpcOpts = append(rpcOpts, opt)
	}
	messageOpts := []signature.MessageOption{}
	for _, opt := range opts {
		messageOpts = append(messageOpts, opt)
	}
	args := &common.MethodArgs{
		MethodName: common.SignMessageMethodName,
		SignMessage: &common.SignMessageArgs{
			SignOptions: &common.SignOptions{
				RPCOptions:     getRPCOptions(rpcOpts),
				MessageOptions: getMessageOptions(messageOpts),
			},
		},
	}
	ctx := c.Ctx
	if args.SignMessage.SignOptions.CtxDeadline != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, *args.SignMessage.SignOptions.CtxDeadline)
		defer cancel()
	}
	resp, err := c.invokePlugin(ctx, message, args)
	if err != nil {
		return nil, err
	}
	signature := resp.SignMessage.Signature
	return signature, nil
}

func (c PluginClient) VerifySignature(sig io.Reader, message io.Reader, opts ...signature.VerifyOption) error {
	rpcOpts := []signature.RPCOption{}
	for _, opt := range opts {
		rpcOpts = append(rpcOpts, opt)
	}
	messageOpts := []signature.MessageOption{}
	for _, opt := range opts {
		messageOpts = append(messageOpts, opt)
	}
	sigBytes, err := io.ReadAll(sig)
	if err != nil {
		return fmt.Errorf("reading signature: %w", err)
	}
	args := &common.MethodArgs{
		MethodName: common.VerifySignatureMethodName,
		VerifySignature: &common.VerifySignatureArgs{
			Signature: &sigBytes,
			VerifyOptions: &common.VerifyOptions{
				RPCOptions:     getRPCOptions(rpcOpts),
				MessageOptions: getMessageOptions(messageOpts),
			},
		},
	}
	ctx := c.Ctx
	if args.VerifySignature.VerifyOptions.CtxDeadline != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, *args.VerifySignature.VerifyOptions.CtxDeadline)
		defer cancel()
	}
	_, err = c.invokePlugin(ctx, message, args)
	if err != nil {
		return err
	}
	return nil
}

func getRPCOptions(opts []signature.RPCOption) *common.RPCOptions {
	ctx := context.TODO()
	rpcAuth := options.RPCAuth{}
	var keyVersion string
	var remoteVerification bool
	for _, opt := range opts {
		opt.ApplyRPCAuthOpts(&rpcAuth)
		opt.ApplyContext(&ctx)
		opt.ApplyKeyVersion(&keyVersion)
		opt.ApplyRemoteVerification(&remoteVerification)
	}
	var ctxDeadline *time.Time
	if deadline, ok := ctx.Deadline(); ok {
		ctxDeadline = &deadline
	}
	return &common.RPCOptions{
		CtxDeadline:        ctxDeadline,
		KeyVersion:         &keyVersion,
		RPCAuth:            &rpcAuth,
		RemoteVerification: &remoteVerification,
	}
}

func getMessageOptions(opts []signature.MessageOption) *common.MessageOptions {
	var digest []byte
	var signerOpts crypto.SignerOpts
	for _, opt := range opts {
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}
	var hashFunc *crypto.Hash
	if signerOpts != nil {
		hf := signerOpts.HashFunc()
		hashFunc = &hf
	}
	return &common.MessageOptions{
		Digest:   &digest,
		HashFunc: hashFunc,
	}
}
