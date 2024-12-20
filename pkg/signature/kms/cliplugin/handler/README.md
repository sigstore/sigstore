# Handler

This package contains helper methods for plugins written in go. See also: [cliplugin docs](../README.md#implementation).

In `dispatch.go`

* `GetPluginArgs(osArgs []string) (*PluginArgs, error)`. To parse the `PluginArgs`. The plugin author can use the values for some pre-processing, perhaps with the values in `PluginArgs.InitOptions`.
* `Dispatch(stdout io.Writer, stdin io.Reader, pluginArgs *PluginArgs, impl kms.SignerVerifier) (*PluginResp, error)` for auto-invoking the correct interface methods, given an implementation. stdin will be the message argument for the methods that sign and verify data. The plugin author may do post-processing with the returned PluginResp.
* `WriteResponse(wr io.Writer, resp *PluginResp) error`, should the author wish to construct and return their own PluginResp and exit.
* `WriteErrorResponse(wr io.Writer, err error) error`, should the author wish to simply send an error message and exit.

In `methods.go`

* `Dispatch()` will forward to corresponding functions that correctly deserialize the method `[Method Name]Args` structs just before invoking the real implementations with the deserialized arguments. These functions will then serialize the real implementations' responses into the `[Method Name]Resp` structs.
