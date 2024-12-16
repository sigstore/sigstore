# CLI Plugin

This is a package and module for using custom KMS plugins as separate executables.
It is intended to be used by cosign, but you may use this in your own programs that import sigstore.

## Design

We follow [kubectl's style](https://kubernetes.io/docs/tasks/extend-kubectl/kubectl-plugins/#writing-kubectl-plugins) of plugins. Any language that can create CLI programs can be used to make a plugin.

### Usage

Plugins are separate programs on your system's PATH, named in the scheme `sigstore-kms-[name]`, like `sigstore-kms-my-hsm`. They can be invoked with cosign like `cosign [sub-command] --key "my-hsm://my-key-id" ...
`

### Protocol

The main program will invoke the program with these specifications:

* stdin
  * Data to be signed or verified.
* arg 1
  * A number idnetifying the version of this protocol.
    * In the future we may change this protocol, either the encoding or the formatting of argument and return values.
    These are necessarily breaking changes, and will be major-version bumps to sigstore and cosign.
    When changing the protocol, new versions of sigstore will not maintain backwards compatibility with
    previous protocol versions. If a plugin author wishes, they may branch their plugin program’s behaviour
    to be compatible with multiple versions of the protocol, or multiple major versions of sigstore and cosign.
* arg 2
  * JSON of initialization options and method arguments.
* stdout
  * JSON of method return values.

See [./common/interface.go](./common/interface.go) for the full JSON schema.

The plugin program must first exit before sigstore begins parsing responses.

#### Error Handling

The plugin program’s stderr will be redirected to the main program’s stderr. This way, the main program may also see the plugin program’s debug messages.

Plugin authors may return errors with `PluginResp.ErrorMessage`, but the plugin's exit status will be ignored.

### Implementation

Plugin authors must implement the `kms.SignerVerifier` interface methods in their chosen language. Each method will inbvoke your program once, and the reponse will be parsed from stdout.

Exit status is ignored. Your programs stderr will be redirected to the main program, and errors you wish to return must be serialized in `PluginResp.ErrorMessage` in stdout.

For authors using Go, we vend some helper functions to help you get started.

* `GetPluginArgs(osArgs []string) (*PluginArgs, error)`
  * to parse the `PluginArgs`. The plugin author can use the values for some pre-processing, perhaps with the values in `PluginArgs.InitOptions`.
* `Dispatch(stdout io.Writer, stdin io.Reader, pluginArgs *PluginArgs, impl kms.SignerVerifier) (*PluginResp, error)`
  * for auto-invoking the correct interface methods, given an implementation. stdin will be the message argument for the methods that sign and verify data. The plugin author may do post-processing with the returned PluginResp.
* `WriteResponse(wr io.Writer, resp *PluginResp) error`
  * , should the author wish to construct and return their own PluginResp and exit.
* `WriteErrorResponse(wr io.Writer, err error) error`
  * , should the author simply send an error message and exit.

## Development

Changes to the `SignerVerifier` interface are to be handled in [./signer.go's](./signer.go) `PluginClient` and [./handler/dispatch.go's](./handler/dispatch.go) `Dispatch()`.

### Adding New Methods or Method Options

Adding new methods or options are *not* necessarily breaking changes to the schemas, so we may consider these to be minor version increments, both to the protocol version and the sigstore version.

### Removing Methods

Removing methods, or altering their signatures will break the schemas and will require major version increments, both to the protocl version and the sigstore version.

### Example Plugin

We have an example plugin in [test/cliplugin/localkms](../../../.././test/cliplugin/localkms).

1. Compile cosign and the plugin

    ```
    go build -C cosign/cmd/cosign -o `pwd`/cosign-cli
    go build -C sigstore/test/cliplugin/localkms -o `pwd`/sigstore-kms-localkms
    ```

2. Generate an RSA key

    ```
    export PATH="$PATH:`pwd`"
    cosign-cli generate-key-pair --kms localkms://`pwd`/key.pem
    cat cosign.pub
    ```

TODO: implement more methods

### Testing

Unit tests against a pre-compiled plugin program are in [./signer_program_test.go](./signer_program_test.go), and can be invoked like

```
export PATH=$PATH:[folder containing plugin program]
go test -C ./pkg/signature/kms/cliplugin -v -tags=signer_program ./... -key-resource-id [my-kms]://[my key ref]
```
