# Local KMS

This module is an example implementation of a KMS plugin.
See [clicplugin](../../../pkg/signature/kms/cliplugin/).

The Key Ref is a path to am RSA private key on your system.
The for the sigstore library to invoke the plugin program, the binary must be on your system's PATH.

```shell
mkdir -p ../bin
go build -o ../bin/sigstore-kms-localkms

cosign [sub command] [options] --key localkms://[path to private key]
```