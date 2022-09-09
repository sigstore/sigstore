# sigstore go library
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/sigstore.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:sigstore) [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/5716/badge)](https://bestpractices.coreinfrastructure.org/projects/5716)

sigstore/sigstore is a go library that provides API's for common sigstore
features. If you need to develop a go based application that leverages
sigstore, you're in the right place.

sigstore/sigstore is utilized by various other clients and projects including 
fulcio, rekor, cosign and others such as tektoncd/chains.

This library currently provides:

* A key generation / signing interface (support for ecdsa, ed25519, rsa, DSSE (in-toto))
* OpenID Connect fulcio client code for keyless style flows.

The following KMS systems are available:
* AWS Key Management Service
* Azure Key Vault
* HashiCorp Vault
* Google Cloud Platform Key Management Service

For example code, look at the relevant test code for each main code file.

## Contributing

Please see [CONTRIBUTORS.md](CONTRIBUTORS.md) for details on how to contribute.

## Fuzzing
The fuzzing tests are within https://github.com/sigstore/sigstore/tree/main/test/fuzz

## Security

Should you discover any security issues, please refer to sigstores [security
process](https://github.com/sigstore/community/blob/main/SECURITY.md)

For container signing, you want [cosign](https://github.com/sigstore/cosign)
