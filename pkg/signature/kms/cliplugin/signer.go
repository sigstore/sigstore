package cliplugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
)

var (
	ErrorExecutingPlugin    = errors.New("error executing plugin program")
	ErrorResponseParseError = errors.New("parsing plugin response")
	ErrorPluginReturnError  = errors.New("plugin returned error")
	ErrorParsingPluginName  = errors.New("parsing plugin name")
	ErrorUnsupportedMethod  = errors.New("unsupported methodArgs")
)

// PluginClient implements kms.SignerVerifier with calls to our plugin program.
// The initial Ctx is preserved for use only by the plugin program if plugin authors desire to.
type PluginClient struct {
	kms.SignerVerifier
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

// TODO: Additonal methods to be implemented

func (c PluginClient) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	// TODO: extract values from signature.SignOption
	args := &common.MethodArgs{
		MethodName: common.SignMessageMethodName,
	}
	// TODO: use the extracted context deadline from opts.
	resp, err := c.invokePlugin(context.TODO(), message, args)
	if err != nil {
		return nil, err
	}
	signature := resp.SignMessage.Signature
	return signature, nil
}
