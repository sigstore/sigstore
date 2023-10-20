# Cryptographic Algorithms / KMS Policy

sigstore/sigstore contains interfaces to provide signing and verification options with in-memory and cloud-provider KMS keys.
This document specifies the currently supported signing and hashing algorithms and KMS providers, along with criteria for proposing new algorithms and providers.

## Signing algorithms

Sigstore supports the following signing algorithms:

* RSA, with key sizes:
  * 2048
  * 3072
  * 4096
* ECDSA, with curves:
  * NIST P-224 (secp224r1)
  * NIST P-256 (secp256r1, prime256v1)
  * NIST P-384 (secp384r1)
  * NIST P-521 (secp521r1)
* Ed25519

Sigstore supports both the RSA-PKCS#1v1.5 and RSA-PSS signature schemes, and will only support well-known schemes implemented by the Golang crypto package.
Sigstore will not support non-standard RSA key sizes. Sigstore will only support well-known ECDSA curves implemented by the Golang crypto package.

### Post-quantum signing algorithms

Post-quantum (PQ) computing will require new signing algorithms, as modern signing algorithms that depend on the difficulty of the integer factorization problem and discrete logarithm problem will be easily broken by quantum computing.

Sigstore does not yet have a stance on which PQ signing algorithms will be supported.
NIST is [currently selecting](https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022)
a set of recommended signing algorithms. We present some high-level thoughts on the top candidates and existing hash-based schemes:

* LMS/XMSS - Hash-based signature schemes that are quick to produce and verify with a small public key size, but larger in signature size.
  NIST selected these two algorithms for hash-based signature schemes in 2020 ([SP 800.208](https://csrc.nist.gov/pubs/sp/800/208/final)).
  LMS/XMSS have a significant drawback in that these signatures are stateful. Signing key reuse over a given amount breaks the security of LMS/XMSS.
  These signing algorithms could work well for Sigstore's usage of ephemeral keys, since a key should only be used once for a signing event. However, these would not work for:
  * Self-managed keys that may be reused, unless the signer keeps track of usage
  * CAs (Fulcio) that sign certificates or transparency logs (Rekor) that sign log checkpoints, unless the services keep track of usage. For Sigstore, service key rotation is currently a manual process involving a TUF root signing event, so we are unable to automatically rotate service key material.
  * TUF metadata itself, which is signed, unless the metadata keys are rotated out before being reused too frequently.
* SPHINCS+ - Hash-based signature scheme that is quick to verify with a small public key size, but with a very large signature size and is very slow to verify.
  Note that this scheme is stateless, so reuse is not a concern. Neither of the drawbacks are a significant concern in code signing,
  although storage costs would increase for transparency log operators. Code signing can be slow, because it's a one-time process that can be automated.
* CRYSTALS-Dilithium - Lattice-based signature scheme with fast signing and verification, but larger public key and signature sizes.
  Dilithium offers good tradeoffs between signing/verification time and public key/signature sizes, though the larger key and signature sizes will increase storage costs for transparency log operators. 
* Falcon - Lattice-based signature scheme with fast verification, with larger public key and signature sizes, but smaller than Dilithium, and slower signing than Dilithium.
  Like Dilithium, Falcon offers good tradeoffs between signing/verification time and public key/signature sizes.
  However, Falcon is likely to be a complex implementation and there are some concerns around its use of floating point operations.

This is not an exhaustive list, and this list may be updated as candidates are removed or if new signing algorithms are designed.
We recommend reading Cloudflare's [scheme comparison](https://blog.cloudflare.com/sizing-up-post-quantum-signatures/)
and [a deep dive into signing](https://blog.cloudflare.com/post-quantum-signatures/) to learn more.

We will add support for PQ signing algorithms once the Golang crypto package adopts these signing algorithms.
We will accept PRs with experimental support for NIST candidates once well-known and vetted Golang libraries are created for PQ signing.
We will not accept PRs for PQ signing algorithms based on C implementations with a Go shim, though we encourage experimentation on forks and welcome any feedback on recommended algorithms in a GitHub discussion.

## Hashing algorithms

Sigstore supports the following hashing algorithms:

* SHA256
* SHA384
* SHA512

Supported but discouraged algorithms include:

* SHA1 - SHA1 is allowed only in limited cases for compatibility with certain file types that require SHA1.
* SHA224

Sigstore will add support for SHA3 once the SHA3 implementation is moved from Golang's x/crypto package to its standard crypto package.

## KMS providers

Sigstore currently supports the following KMS providers:

* Amazon Web Services 
* Google Cloud Platform
* Hashicorp Vault
* Microsoft Azure

PRs for new providers will only be accepted if the following conditions are met:

* Maintainers of Sigstore are familiar with the provider and able to debug issues with the provider and with end-to-end tests.
* There is significant community interest in the KMS provider.
* The provider is well-maintained with regular contributions (if open source) and releases should be frequent. The license must be compatible with the Apache 2.0 license.
* The provider has not had significant security and/or privacy vulnerabilities. Sigstore reserves the right to remove support for a provider if it is shown to not take security and/or privacy seriously.
* The PR contains sufficient unit and end-to-end tests.

Please file an issue before starting implementation of the KMS provider to confirm that the provider meets these requirements.

We encourage maintaining a private fork of sigstore/sigstore and Cosign if you wish to support a provider that does not meet these requirements.

Sigstore's roadmap for future client updates includes a porcelain-and-plumbing model. One goal will be to add plugin support such that users could bring their own signing and verification modules without requiring a fork of Cosign.
