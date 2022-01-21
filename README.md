# sigstore framework
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/sigstore.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:sigstore)

sigstore/sigstore is a generic library / framework that is utilized by various other
clients and projects including fulcio (webPKI), cosign (container and OCI signing tool)
and tektoncd/chains (Supply Chain Security in Tekton Pipelines).

sigstore is a good candidate for anyone wanting to develop go based clients / systems
and utilise existing go modules for common sigstore functionality.

This library currently provides:

* A signing interface (support for ecdsa, ed25519, rsa, DSSE (in-toto))
* OpenID Connect fulcio client code

The following KMS systems are available:
* AWS Key Management Service
* Azure Key Vault
* HashiCorp Vault
* Google Cloud Platform Key Management Service

For example code, look at the relevant test code for each main code file.

## Fuzzing
The fuzzing tests are within https://github.com/sigstore/sigstore/tree/main/test/fuzz

## Security

Should you discover any security issues, please refer to sigstores [security
process](https://github.com/sigstore/community/blob/main/SECURITY.md)

For container signing, you want [cosign](https://github.com/sigstore/cosign)
