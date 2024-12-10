package cliplugin

import (
	"bytes"
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

// PluginClient implements kms.SignerVerifier with calls to our plugin program.
// The initial Ctx is preserved for use only by the plugin program if plugin authors desire to.
type PluginClient struct {
	kms.SignerVerifier
	// Ctx will not be directly used in PluginClient's methods, nor within Command objects.
	// Instead, we will pass this initial Ctx's deadline, if it exists, within PluginArgs.InitOptions.
	// Plugin authors may use it, if desired, for KMS-specific initialization tasks.
	executable      string
	initOptions     common.InitOptions
	makeCommandFunc makeCommandFunc
}

func newPluginClient(executable string, initOptions *common.InitOptions, makeCommand makeCommandFunc) *PluginClient {
	pluginClient := &PluginClient{
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
	ctx, rpcOptions := getRPCOptions(rpcOpts)
	args := &common.MethodArgs{
		MethodName: common.PublicKeyMethodName,
		PublicKey: &common.PublicKeyArgs{
			PublicKeyOptions: &common.PublicKeyOptions{
				RPCOptions: rpcOptions,
			},
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
	ctx, rpcOptions := getRPCOptions(rpcOpts)
	args := &common.MethodArgs{
		MethodName: common.SignMessageMethodName,
		SignMessage: &common.SignMessageArgs{
			SignOptions: &common.SignOptions{
				RPCOptions:     rpcOptions,
				MessageOptions: getMessageOptions(messageOpts),
			},
		},
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
	ctx, rpcOptions := getRPCOptions(rpcOpts)
	args := &common.MethodArgs{
		MethodName: common.VerifySignatureMethodName,
		VerifySignature: &common.VerifySignatureArgs{
			Signature: &sigBytes,
			VerifyOptions: &common.VerifyOptions{
				RPCOptions:     rpcOptions,
				MessageOptions: getMessageOptions(messageOpts),
			},
		},
	}
	_, err = c.invokePlugin(ctx, message, args)
	if err != nil {
		return err
	}
	return nil
}

func (c PluginClient) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	signer := CryptoSigner{
		pluginClient: &c,
		errFunc:      errFunc,
		ctx:          ctx,
	}
	signerOpts := c.initOptions.HashFunc
	return signer, signerOpts, nil
}

// getRPCOptions extracts properties of all of opts into struct ready for serializing.
// The returned context will be context.TODO() if not provided within the opts.
func getRPCOptions(opts []signature.RPCOption) (context.Context, *common.RPCOptions) {
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
	return ctx, &common.RPCOptions{
		CtxDeadline:        ctxDeadline,
		KeyVersion:         &keyVersion,
		RPCAuth:            &rpcAuth,
		RemoteVerification: &remoteVerification,
	}
}

// getMessageOptions extracts properties of all of opts into struct ready for serializing.
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

// CryptoSigner wraps around the PluginClient.
type CryptoSigner struct {
	pluginClient *PluginClient
	errFunc      func(error)
	ctx          context.Context
}

// Public returns the public key.
func (c CryptoSigner) Public() crypto.PublicKey {
	publicKey, err := c.pluginClient.PublicKey()
	if err != nil {
		panic(err)
	}
	return publicKey
}

// Sign signs the digest with the PluginClient. rand is not used.
func (c CryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// no message is given, only a digest
	emptyMessage := bytes.NewReader([]byte{})
	signOpts := []signature.SignOption{
		// We do not pass the context PluginClient's initial context to this method.
		options.WithCryptoSignerOpts(opts),
		options.WithDigest(digest),
		options.WithKeyVersion(c.pluginClient.initOptions.KeyVersion),
	}
	return c.pluginClient.SignMessage(emptyMessage, signOpts...)
}
