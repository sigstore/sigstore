# Go Coverage tool

The goal of the coverage tool is to measure the coverage of the code base for Golang.

## Usage
Execute the following command to get the coverage and store it in a file:
1. `go test  -coverprofile=coverage ./... | THRESHOLD_FILE=./coverage.json COVERAGE_PERCENTAGE=70 go run ./hack/codecoverage/main.go`
2. The `THRESHOLD_FILE` is the path to the file containing the coverage threshold.
3. The THRESHOLD_FILE contains the percentage of the code coverage that is required to pass for certain packages. This is usually because they don't match the desired coverage.
```json
    {
    "github.com/sigstore/sigstore/pkg/cryptoutils": 71.2,
    "github.com/sigstore/sigstore/pkg/oauth/internal" :88.7,
    "github.com/sigstore/sigstore/pkg/oauth/oidc": 0.8,
    "github.com/sigstore/sigstore/pkg/oauthflow": 36.4,
    "github.com/sigstore/sigstore/pkg/signature": 66.5,
    "github.com/sigstore/sigstore/pkg/signature/dsse": 77.1,
    "github.com/sigstore/sigstore/pkg/signature/kms": 50.0,
    "github.com/sigstore/sigstore/pkg/signature/kms/aws": 5.1,
    "github.com/sigstore/sigstore/pkg/signature/kms/azure": 11.3,
    "github.com/sigstore/sigstore/pkg/signature/kms/fake": 85.3,
    "github.com/sigstore/sigstore/pkg/signature/kms/gcp": 18.8,
    "github.com/sigstore/sigstore/pkg/signature/kms/hashivault":3.6,
    "github.com/sigstore/sigstore/pkg/signature/payload": 43.8,
    "github.com/sigstore/sigstore/pkg/signature/ssh": 65.3,
    "github.com/sigstore/sigstore/pkg/tuf": 66.2
    }
```
3. The `COVERAGE_PERCENTAGE` is the percentage of the code coverage that is required to pass for all the packages except the ones that are mentioned in the `THRESHOLD_FILE`.
4. The coverage tool will fail if the coverage is below the threshold for any package.
``` shell
2022/07/29 16:14:41 github.com/sigstore/sigstore/pkg/foo is below the threshold of 71.000000
exit status 1
```

### Design choices

1. The coverage tool should not depend on any other tools. It should work of the results from the `go test` command.
2. Coverage threshold should be configurable for each repository - for example `70%` within the repository.
3. A setting file should override the coverage threshold for a given package within the repository. `github.com/foo/bar/xyz : 61`
4. The coverage tool should use native `go` tools and shouldn't depend on external vendors.
5. The coverage tool should be configurable as part of the PR to fail if the desired threshold is not met.
6. Contributors should be able to run it locally if desired before doing a PR.
