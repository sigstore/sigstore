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
	"os/exec"
	"strings"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigkms "github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

const (
	SupportedAlgorithmsMethodName = "SupportedAlgorithms"
	PublicKeyMethodName           = "publicKey"
	SignMessageMethodName         = "signMessage"
	ReferenceScheme               = "sigstore-kms-"
	ProtocolVersion               = "1"
)

var (
	ErrorExecutingPlugin         = errors.New("error executing plugin program")
	ErrorResponseParseError      = errors.New("parsing plugin response")
	ErrorPluginReturnError       = errors.New("plugin returned error")
	ErrorParsingPluginBinaryName = errors.New("parsing plugin binary name")
)

func init() {
	sigkms.AddProvider(ReferenceScheme, func(ctx context.Context, keyResourceID string, hashFunc crypto.Hash, opts ...signature.RPCOption) (sigkms.SignerVerifier, error) {
		return LoadSignerVerifier(ctx, keyResourceID, hashFunc)
	})
}

func LoadSignerVerifier(ctx context.Context, inputKeyresourceID string, hashFunc crypto.Hash) (sigkms.SignerVerifier, error) {
	parts := strings.SplitN(inputKeyresourceID, "://", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w: expected format: [binary name]://[key ref], got: %s", ErrorParsingPluginBinaryName, inputKeyresourceID)
	}
	executable, keyResourceID := parts[0], parts[1]
	InitOptions := &InitOptions{
		ProtocolVersion: ProtocolVersion,
		KeyResourceID:   keyResourceID,
		HashFunc:        hashFunc,
	}
	pluginClient := newPluginClient(ctx, executable, InitOptions, makeCommand)
	return pluginClient, nil
}

func newPluginClient(ctx context.Context, executable string, initOptions *InitOptions, makeCommand makeCommandFunc) *PluginClient {
	pluginClient := &PluginClient{
		Ctx:             ctx,
		executable:      executable,
		initOptions:     *initOptions,
		makeCommandFunc: makeCommand,
	}
	return pluginClient
}

type PluginClient struct {
	sigkms.SignerVerifier
	Ctx             context.Context
	executable      string
	initOptions     InitOptions
	makeCommandFunc makeCommandFunc
}

type Plugin struct {
}

type SupportedAlgorithmsArgs struct {
}

type SupportedAlgorithmsResp struct {
	SupportedAlgorithms []string
}

type PluginArgs struct {
	Method             string                   `json:"method"`
	SuportedAlgorithms *SupportedAlgorithmsArgs `json:"suportedAlgorithms,omitempty"`
	PublicKey          *PublicKeyArgs           `json:"publicKey,omitempty"`
	SignMessage        *SignMessageArgs         `json:"signMessage,omitempty"`
	InitOptions        *InitOptions             `json:"initOptions"`
}

type PluginResp struct {
	ErrorMessage        string                   `json:"errorMessage,omitempty"`
	SupportedAlgorithms *SupportedAlgorithmsResp `json:"supportedAlgorithms,omitempty"`
	PublicKey           *PublicKeyResp           `json:"publicKey,omitempty"`
	SignMessage         *SignMessageResp         `json:"signMessage,omitempty"`
}

type command interface {
	Output() ([]byte, error)
}

type makeCommandFunc func(ctx context.Context, stdin io.Reader, stderr io.Writer, name string, args ...string) command

func makeCommand(ctx context.Context, stdin io.Reader, stderr io.Writer, name string, args ...string) command {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = stdin
	cmd.Stderr = stderr
	return cmd
}

func (c PluginClient) invokePlugin(ctx context.Context, stdin io.Reader, args *PluginArgs) (*PluginResp, error) {
	args.InitOptions = &c.initOptions
	argsEnc, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	cmd := c.makeCommandFunc(ctx, stdin, os.Stderr, c.executable, ProtocolVersion, string(argsEnc))
	// we won't look at exit status as a pottential error.
	// If a program exit(1), the only debugging is to either parse the the returned error in stdout,
	// or for the user to examine the sterr logs.
	stdout, _ := cmd.Output()
	// slog.Info("invokePlugin", "stdout", stdout)
	var resp PluginResp
	if unmarshallErr := json.Unmarshal(stdout, &resp); unmarshallErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrorResponseParseError, unmarshallErr)
	}
	if resp.ErrorMessage != "" {
		return nil, fmt.Errorf("%w: %s", ErrorPluginReturnError, resp.ErrorMessage)
	}
	// if cmdErr != nil {
	// 	return fmt.Errorf("%w: %w", ErrorExecutingPlugin, cmdErr)
	// }
	// slog.Info("invokePlugin", "unmarshall", resp)
	return &resp, nil
}

func (c PluginClient) SupportedAlgorithms() (result []string) {
	args := &PluginArgs{
		Method:             SupportedAlgorithmsMethodName,
		SuportedAlgorithms: &SupportedAlgorithmsArgs{},
	}
	resp, err := c.invokePlugin(c.Ctx, nil, args)
	if err != nil {
		log.Fatal(err)
	}
	return resp.SupportedAlgorithms.SupportedAlgorithms
}

type PublicKeyArgs struct {
	KeyVersion string
}

type PublicKeyResp struct {
	PublicKeyPEM []byte
}

func (c PluginClient) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	ctx := c.Ctx
	keyVersion := "1"
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyKeyVersion(&keyVersion)
	}
	args := &PluginArgs{
		Method: PublicKeyMethodName,
		PublicKey: &PublicKeyArgs{
			KeyVersion: keyVersion,
		},
	}
	// slog.Info("client", "pi", c.pluginInvoker)
	resp, err := c.invokePlugin(ctx, nil, args)
	if err != nil {
		return nil, err
	}
	// slog.Warn("PublicKey", "pem", resp.PublicKey.PublicKeyPEM)
	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey(resp.PublicKey.PublicKeyPEM)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

type SignMessageArgs struct {
	HashFunc   crypto.Hash `json:"hashFunc"`
	KeyVersion string      `json:"keyVersion"`
}

type SignMessageResp struct {
	Signature []byte `json:"signature"`
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
	args := &PluginArgs{
		Method: SignMessageMethodName,
		SignMessage: &SignMessageArgs{
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

func WriteResponse(wr io.Writer, resp *PluginResp) error {
	enc, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	fmt.Fprint(wr, string(enc))
	return nil
}

type InitOptions struct {
	ProtocolVersion string      `json:"protocolVersion"`
	KeyResourceID   string      `json:"keyResourceID"`
	KeyVersion      string      `json:"keyVersion,omitempty"`
	HashFunc        crypto.Hash `json:"hashFunc"`
}

func GetPluginArgs(osArgs []string) (*PluginArgs, error) {
	argsStr := osArgs[2]
	var args PluginArgs
	if err := json.Unmarshal([]byte(argsStr), &args); err != nil {
		return nil, err
	}
	return &args, nil
}

func ParseArgs(argsStr string) (*PluginArgs, error) {
	var args PluginArgs
	if err := json.Unmarshal([]byte(argsStr), &args); err != nil {
		return nil, err
	}
	return &args, nil
}

type ErrorResp struct {
	Message string
}

func Dispatch(stdout io.Writer, stdin io.Reader, args *PluginArgs, impl sigkms.SignerVerifier) (*PluginResp, error) {
	var resp PluginResp
	var err error
	switch args.Method {
	case SupportedAlgorithmsMethodName:
		resp.SupportedAlgorithms, err = SupportedAlgorithms(stdin, args.SuportedAlgorithms, impl)
	case PublicKeyMethodName:
		resp.PublicKey, err = PublicKey(stdin, args.PublicKey, impl)
	case SignMessageMethodName:
		resp.SignMessage, err = SignMessage(stdin, args.SignMessage, impl)
	}
	if err != nil {
		resp.ErrorMessage = err.Error()
	}
	WriteResponse(stdout, &resp)
	return &resp, err
}

func WriteErrorResponse(wr io.Writer, err error) {
	resp := &PluginResp{
		ErrorMessage: err.Error(),
	}
	WriteResponse(wr, resp)
}

func SupportedAlgorithms(stdin io.Reader, args *SupportedAlgorithmsArgs, impl sigkms.SignerVerifier) (*SupportedAlgorithmsResp, error) {
	supportedAlgorithms := impl.SupportedAlgorithms()
	resp := &SupportedAlgorithmsResp{
		SupportedAlgorithms: supportedAlgorithms,
	}
	return resp, nil
}

func PublicKey(stdin io.Reader, args *PublicKeyArgs, impl sigkms.SignerVerifier) (*PublicKeyResp, error) {
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
	resp := &PublicKeyResp{
		PublicKeyPEM: publicKeyPEM,
	}
	return resp, nil
}

func SignMessage(stdin io.Reader, args *SignMessageArgs, impl sigkms.SignerVerifier) (*SignMessageResp, error) {
	opts := []signature.SignOption{
		options.WithKeyVersion(args.KeyVersion),
		options.WithCryptoSignerOpts(args.HashFunc),
	}
	signature, err := impl.SignMessage(stdin, opts...)
	if err != nil {
		return nil, err
	}
	resp := &SignMessageResp{
		Signature: signature,
	}
	return resp, nil
}
