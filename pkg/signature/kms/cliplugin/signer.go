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
	sigkms "github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

var (
	ErrorExecutingPlugin         = errors.New("error executing plugin program")
	ErrorResponseParseError      = errors.New("parsing plugin response")
	ErrorPluginReturnError       = errors.New("plugin returned error")
	ErrorParsingPluginBinaryName = errors.New("parsing plugin binary name")
	ErrorUnsupportedMethod       = errors.New("unsupported method")
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

// invokePlugin invokes the plugin program and parses its response.
// Here we use a generic so we can get compile-time errors for incorrect methodArgs,
// instead of making methodArgs be an interface{}
func invokePlugin[
	T common.DefaultAlgorithmArgs |
		common.SupportedAlgorithmsArgs |
		common.PublicKeyArgs |
		common.CreateKeyArgs |
		common.SignMessageArgs,
](
	ctx context.Context,
	client *PluginClient,
	stdin io.Reader,
	methodArgs *T,
) (*common.PluginResp, error) {
	args := &common.MethodArgs{}
	// we can't type switch on generics, so we must convert it to any.
	switch a := any(methodArgs).(type) {
	case *common.DefaultAlgorithmArgs:
		args.MethodName = common.DefaultAlgorithmMethodName
		args.DefaultAlgorithm = a
	case *common.SupportedAlgorithmsArgs:
		args.MethodName = common.SupportedAlgorithmsMethodName
		args.SuportedAlgorithms = a
	case *common.PublicKeyArgs:
		args.MethodName = common.PublicKeyMethodName
		args.PublicKey = a
	case *common.CreateKeyArgs:
		args.MethodName = common.CreateKeyMethodName
		args.CreateKey = a
	case *common.SignMessageArgs:
		args.MethodName = common.SignMessageMethodName
		args.SignMessage = a
	default:
		return nil, fmt.Errorf("%w: %v", ErrorUnsupportedMethod, a)
	}
	pluginArgs := &common.PluginArgs{
		InitOptions: &client.initOptions,
		MethodArgs:  args,
	}
	argsEnc, err := json.Marshal(pluginArgs)
	if err != nil {
		return nil, err
	}
	cmd := client.makeCommandFunc(ctx, stdin, os.Stderr, client.executable, common.ProtocolVersion, string(argsEnc))
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
	args := &common.DefaultAlgorithmArgs{}
	resp, err := invokePlugin(context.TODO(), &c, nil, args)
	if err != nil {
		log.Fatal(err)
	}
	return resp.DefaultAlgorithm.DefaultAlgorithm
}

func (c PluginClient) SupportedAlgorithms() (result []string) {
	args := &common.SupportedAlgorithmsArgs{}
	resp, err := invokePlugin(context.TODO(), &c, nil, args)
	if err != nil {
		log.Fatal(err)
	}
	return resp.SupportedAlgorithms.SupportedAlgorithms
}

func getRPCOption(opts []signature.RPCOption) *common.RPCOption {
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
	return &common.RPCOption{
		CtxDeadline:        ctxDeadline,
		KeyVersion:         &keyVersion,
		RPCAuth:            &rpcAuth,
		RemoteVerification: &remoteVerification,
	}
}

func (c PluginClient) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	rpcOpts := []signature.RPCOption{}
	for _, opt := range opts {
		rpcOpts = append(rpcOpts, opt)
	}
	args := &common.PublicKeyArgs{
		PublicKeyOptions: common.PublicKeyOptions{
			RPCOption: getRPCOption(rpcOpts),
		},
	}
	ctx := c.Ctx
	if args.PublicKeyOptions.CtxDeadline != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, *args.PublicKeyOptions.CtxDeadline)
		defer cancel()
	}
	resp, err := invokePlugin(ctx, &c, nil, args)
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
	args := &common.CreateKeyArgs{
		Algorithm: algorithm,
	}
	resp, err := invokePlugin(ctx, &c, nil, args)
	if err != nil {
		return nil, err
	}
	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey(resp.CreateKey.PublicKeyPEM)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

func getMessageOption(opts []signature.MessageOption) *common.MessageOption {
	var digest []byte
	var signerOpts crypto.SignerOpts
	for _, opt := range opts {
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}
	hashFunc := signerOpts.HashFunc()
	return &common.MessageOption{
		Digest:   &digest,
		HashFunc: &hashFunc,
	}
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
	args := &common.SignMessageArgs{
		SignOptions: common.SignOptions{
			RPCOption:     getRPCOption(rpcOpts),
			MessageOption: getMessageOption(messageOpts),
		},
	}
	ctx := c.Ctx
	if args.SignOptions.CtxDeadline != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, *args.SignOptions.CtxDeadline)
		defer cancel()
	}
	resp, err := invokePlugin(ctx, &c, message, args)
	if err != nil {
		return nil, err
	}
	signature := resp.SignMessage.Signature
	return signature, nil
}

// func (c PluginClient) VerifySignature(signature io.Reader, message io.Reader, opts ...signature.VerifyOption) error {

// }
