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
	return &PluginClient{
		ctx:        ctx,
		executable: executable,
		initOptions: InitOptions{
			ProtoclVersion: ProtocolVersion,
			KeyResourceID:  keyResourceID,
			HashFunc:       hashFunc,
		},
	}, nil
}

type PluginClient struct {
	sigkms.SignerVerifier
	ctx         context.Context
	executable  string
	initOptions InitOptions
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
	MethodArgs         interface{}              `json:"methodArgs"`
	SuportedAlgorithms *SupportedAlgorithmsArgs `json:"supportedAlgorithms,omitempty"`
	PublicKey          *PublicKeyArgs           `json:"publicKey,omitempty"`
	SignMessage        *SignMessageArgs         `json:"signMessage,omitempty"`
	InitOptions        *InitOptions
}

type Resp struct {
	Error               *ErrorResp               `json:"error,omitempty"`
	SupportedAlgorithms *SupportedAlgorithmsResp `json:"supportedAlgorithms,omitempty"`
	PublicKey           *PublicKeyResp           `json:"publicKey,omitempty"`
	SignMessage         *SignMessageResp         `json:"signMessage,omitempty"`
}

func (c PluginClient) invokePlugin(ctx context.Context, executable string, stdin io.Reader, args *PluginArgs, resp *Resp) error {
	// slog.Info("invk")
	argsEnc, err := json.Marshal(args)
	if err != nil {
		return err
	}
	// slog.Info("invokePlugin", "init", initOptionsEnc, "args", argsEnc)
	cmd := exec.CommandContext(ctx, executable, ProtocolVersion, string(argsEnc))

	cmd.Stdin = stdin
	cmd.Stderr = os.Stderr

	// we won't look at exit status as a pottential error.
	// If a program exit(1), the only debugging is to either parse the the returned error in stdout,
	// or for the user to examine the sterr logs.
	stdout, _ := cmd.Output()
	if unmarshallErr := json.Unmarshal(stdout, resp); unmarshallErr != nil {
		return fmt.Errorf("%w: %w", ErrorResponseParseError, unmarshallErr)
	}
	if resp.Error != nil {
		return fmt.Errorf("%w: %s", ErrorPluginReturnError, resp.Error.Message)
	}
	// if cmdErr != nil {
	// 	return fmt.Errorf("%w: %w", ErrorExecutingPlugin, cmdErr)
	// }
	// slog.Info("invokePlugin", "unmarshall", resp)
	return nil
}

func (c PluginClient) SupportedAlgorithms() (result []string) {
	args := &PluginArgs{
		Method:             SupportedAlgorithmsMethodName,
		SuportedAlgorithms: &SupportedAlgorithmsArgs{},
		InitOptions:        &c.initOptions,
	}
	var resp Resp
	if err := c.invokePlugin(c.ctx, c.executable, nil, args, &resp); err != nil {
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
	ctx := c.ctx
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
		InitOptions: &c.initOptions,
	}
	var resp Resp
	if err := c.invokePlugin(ctx, c.executable, nil, args, &resp); err != nil {
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
	HashFunc   crypto.Hash
	KeyVersion string
}

type SignMessageResp struct {
	Signature []byte
}

func (c PluginClient) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	ctx := c.ctx
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
		InitOptions: &c.initOptions,
	}
	var resp Resp
	if err := c.invokePlugin(ctx, c.executable, message, args, &resp); err != nil {
		return nil, err
	}
	signature := resp.SignMessage.Signature
	return signature, nil
}

func WriteResponse(resp *Resp) error {
	enc, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stdout, string(enc))
	return nil
}

type InitOptions struct {
	ProtoclVersion string
	KeyResourceID  string
	KeyVersion     string
	HashFunc       crypto.Hash
}

func GetPluginArgs(osArgs []string) (*PluginArgs, error) {
	argsStr := osArgs[2]
	var args PluginArgs
	// slog.Info("parseargs2", "argsstr", argsStr)
	if err := json.Unmarshal([]byte(argsStr), &args); err != nil {
		return nil, err
	}
	return &args, nil
}

func ParseArgs(argsStr string) (*PluginArgs, error) {
	var args PluginArgs
	// slog.Info("parseargs2", "argsstr", argsStr)
	if err := json.Unmarshal([]byte(argsStr), &args); err != nil {
		return nil, err
	}
	return &args, nil
}

type ErrorResp struct {
	Message string
}

func Dispatch(stdin io.Reader, args *PluginArgs, impl sigkms.SignerVerifier) (*Resp, error) {
	var resp Resp
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
		resp.Error = &ErrorResp{Message: err.Error()}
	}
	WriteResponse(&resp)
	return &resp, err
}

func WriteErrorResponse(err error) {
	resp := &Resp{
		Error: &ErrorResp{Message: err.Error()},
	}
	WriteResponse(resp)
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
	message := os.Stdin
	signature, err := impl.SignMessage(message, opts...)
	if err != nil {
		return nil, err
	}
	resp := &SignMessageResp{
		Signature: signature,
	}
	return resp, nil
}

type PluginHandler struct {
	Impl sigkms.SignerVerifier
}

func (h PluginHandler) SignMessage(stdin io.Reader, args *SignMessageArgs) (*SignMessageResp, error) {
	opts := []signature.SignOption{
		options.WithKeyVersion(args.KeyVersion),
		options.WithCryptoSignerOpts(args.HashFunc),
	}
	message := os.Stdin
	signature, err := h.Impl.SignMessage(message, opts...)
	if err != nil {
		return nil, err
	}
	resp := &SignMessageResp{
		Signature: signature,
	}
	return resp, nil
}
