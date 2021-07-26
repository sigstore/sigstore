# sigstore framework

> :warning: Not ready for use yet!

sigstore/sigstore is a generic library that is utilized by various other
clients and projects inc fulcio (webPKI), cosign (container and OCI signing tool)
and tektoncd/chains (Supply Chain Security in Tekton Pipelines).

sigstore is also good candidate for anyone wanting to develop go based clients / systems
and utilise exiting go modules for common sigstore functionality.

## Security

Should you discover any security issues, please refer to sigstores [security
process](https://github.com/sigstore/community/blob/main/SECURITY.md)

For container signing, you want [cosign](https://github.com/sigstore/cosign)
