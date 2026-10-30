# Cryptographic Algorithms / KMS Policy

sigstore/sigstore contains interfaces to provide signing and verification options with in-memory and cloud-provider KMS keys.
This document specifies the currently supported signing and hashing algorithms and KMS providers, along with criteria for proposing new algorithms and providers.

## Signing and hashing algorithms

See the [algorithm registry specification](https://github.com/sigstore/architecture-docs/blob/main/algorithm-registry.md)
for the set of supported algorithms. This document describes the set of algorithms that _may_ be supported
by Sigstore clients. Clients that support only the public-good instance will implement a subset of these
algorithms, as documented in the
[public deployment specification](https://github.com/sigstore/architecture-docs/blob/main/sigstore-public-deployment-spec.md).

New algorithms must be implemented by a Go library, since Fulcio and Rekor will need to be updated to support the new
signing algorithms. We would strongly prefer algorithms are implemented by the standard library, but may accept proposals
that use well-known and vetted libraries, and that are not based on C implementations with Go bindings.

### Post-quantum signing algorithms

Post-quantum (PQ) computing will require new signing algorithms, as modern signing algorithms that depend on the difficulty of the
integer factorization problem and discrete logarithm problem will be easily broken by quantum computing.

Sigstore will support ML-DSA (FIPS 204). Learn more on [Sigstore’s blog](https://blog.sigstore.dev/pqc-sigstore/).

We are not accepting any other PQC signing algorithms at this time. We will reevaluate support for other algorithms depending on industry requirements in the future, e.g., different algorithms selected by cybersecurity organizations other than NIST.

## KMS providers

Sigstore currently supports the following KMS providers:

* Amazon Web Services 
* Google Cloud Platform
* Hashicorp Vault
* Microsoft Azure
* OpenBao
* [OVHcloud KMS](https://github.com/ovh/sigstore-kms-ovhcloud) (as external plugin)

We offer a plugin interface for new KMS providers. Organizations can independently develop & distribute their plugins without needing downstream updates to libraries like Cosign to support the additional KMS providers. See https://github.com/sigstore/sigstore/tree/main/pkg/signature/kms/cliplugin for more information and https://github.com/sigstore/sigstore/tree/main/test/cliplugin/localkms for an example implementation.

We will not accept PRs for new KMS providers.

You are welcome to file an issue after your KMS provider has been implemented and open-sourced to highlight it on a README in this repository.
