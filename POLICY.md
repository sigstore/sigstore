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
signing algorithms. We would prefer algorithms are implemented by the standard library, but may accept proposals
that use well-known and vetted libraries, and that are not based on C implementations with Go bindings.

### Post-quantum signing algorithms

Post-quantum (PQ) computing will require new signing algorithms, as modern signing algorithms that depend on the difficulty of the
integer factorization problem and discrete logarithm problem will be easily broken by quantum computing.

Sigstore has begun to experiment with support for post-quantum cryptography signing algorithms. We have selected
the two NIST-standardized algorithms, ML-DSA (FIPS 204, Dilithium) and SLH-DSA (FIPS 205, SPHINCS+), for the
initial experiments. While LMS and LMS-OTS could be used to generate signatures with ephemeral keys, they will not
be supported due to requiring state.

Before adding support for a new algorithm under `pkg/signature`, the algorithm will need to be added to the
[algorithm registry specification](https://github.com/sigstore/architecture-docs/blob/main/algorithm-registry.md),
along with an updated to the protobuf specification, updating
[`PublicKeyDetails`](https://github.com/sigstore/protobuf-specs/blob/c30eb14cece57d88c08579197ecfdb57a5f1aba5/protos/sigstore_common.proto#L63)
and [`HashAlgorithm`](https://github.com/sigstore/protobuf-specs/blob/c30eb14cece57d88c08579197ecfdb57a5f1aba5/protos/sigstore_common.proto#L37)
if necessary.

We present some high-level thoughts on the current set of standardized algorithms:

* LMS/XMSS (SP 800-208) - Hash-based signature schemes that are quick to produce and verify with a small public key size, but larger in signature size.
  NIST selected these two algorithms for hash-based signature schemes in 2020 ([SP 800.208](https://csrc.nist.gov/pubs/sp/800/208/final)).
  LMS/XMSS have a significant drawback in that these signatures are stateful. Signing key reuse over a given amount breaks the security of LMS/XMSS.
  These signing algorithms could work well for Sigstore's usage of ephemeral keys, since a key should only be used once for a signing event. However, these would not work for:
  * Self-managed keys that may be reused, unless the signer keeps track of usage
  * CAs (Fulcio) that sign certificates or transparency logs (Rekor) that sign log checkpoints, unless the services keep track of usage. For Sigstore, service key rotation is currently a manual process involving a TUF root signing event, so we are unable to automatically rotate service key material.
  * TUF metadata itself, which is signed, unless the metadata keys are rotated out before being reused too frequently.
* SLH-DSA (FIPS 205, SPHINCS+) - Hash-based signature scheme that is quick to verify with a small public key size, but with a very large signature size and is very slow to verify.
  Note that this scheme is stateless, so reuse is not a concern. Neither of the drawbacks are a significant concern in code signing,
  although storage costs would increase for transparency log operators. Code signing can be slow, because it's a one-time process that can be automated.
* ML-DSA (FIPS 204, Dilithium) - Lattice-based signature scheme with fast signing and verification, but larger public key and signature sizes.
  Dilithium offers good tradeoffs between signing/verification time and public key/signature sizes, though the larger key and signature sizes will increase storage costs for transparency log operators. 
* Falcon - Lattice-based signature scheme with fast verification, with larger public key and signature sizes, but smaller than Dilithium, and slower signing than Dilithium.
  Like Dilithium, Falcon offers good tradeoffs between signing/verification time and public key/signature sizes.
  However, Falcon is likely to be a complex implementation and there are some concerns around its use of floating point operations.

This is not an exhaustive list, and this list may be updated as candidates are removed or if new signing algorithms are designed.
We recommend reading Cloudflare's [scheme comparison](https://blog.cloudflare.com/sizing-up-post-quantum-signatures/),
[a deep dive into signing](https://blog.cloudflare.com/post-quantum-signatures/), and
[another look at PQ signatures](https://blog.cloudflare.com/another-look-at-pq-signatures/) to learn more.

We will add support for PQ signing algorithms once the Go crypto package adopts these signing algorithms.
We will accept PRs with experimental support for NIST-standardized or candidate algorithms using well-known and vetted Go libraries are created for PQ signing.
We will not accept PRs for PQ signing algorithms based on C implementations with Go bindings, though we encourage experimentation on forks and welcome
any feedback on recommended algorithms in a GitHub discussion.

## KMS providers

Sigstore currently supports the following KMS providers:

* Amazon Web Services 
* Google Cloud Platform
* Hashicorp Vault
* Microsoft Azure

We offer a plugin interface for new KMS providers. Organizations can independently develop & distribute their plugins without needing downstream updates to libraries like Cosign to support the additional KMS providers. See https://github.com/sigstore/sigstore/tree/main/pkg/signature/kms/cliplugin for more information and https://github.com/sigstore/sigstore/tree/main/test/cliplugin/localkms for an example implementation.

We will not accept PRs for new KMS providers.

You are welcome to file an issue after your KMS provider has been implemented and open-sourced to highlight it on a README in this repository.
