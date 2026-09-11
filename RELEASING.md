# Releasing sigstore

`sigstore/sigstore` is a Go library containing 5 published modules: the root module `github.com/sigstore/sigstore` and 4 KMS sub-modules under `pkg/signature/kms/{aws,azure,gcp,hashivault}`. Releases are cut directly from `main` via semantic version tags (e.g., `v1.11.0`).

## How to Release

1. **Verify CI**: Ensure all checks on `main` are green (or run `make test lint`).
2. **Create the release** using the `gh` CLI:
   ```bash
   # Create as draft to review generated release notes
   gh release create vX.Y.Z --draft --target main --generate-notes

   # Publish when ready
   gh release edit vX.Y.Z --draft=false
   ```
   *(Or draft/publish via GitHub Web UI under **Releases** &rarr; **Draft a new release** targeting `main` with **Generate release notes**).*

## Automated Triggers

Publishing a `v*` tag automatically triggers:

* **Sub-module Tag Sync** ([`sync-module-tags.yaml`](.github/workflows/sync-module-tags.yaml)):
  A GitHub Actions matrix job automatically creates and pushes matching annotated git tags for all 4 KMS sub-modules on the release commit:
  * `pkg/signature/kms/aws/vX.Y.Z`
  * `pkg/signature/kms/azure/vX.Y.Z`
  * `pkg/signature/kms/gcp/vX.Y.Z`
  * `pkg/signature/kms/hashivault/vX.Y.Z`

## Verification

Confirm that the [Sync tags with all modules](https://github.com/sigstore/sigstore/actions/workflows/sync-module-tags.yaml) workflow completed and [tags are visible](https://github.com/sigstore/sigstore/tags).
