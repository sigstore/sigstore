module github.com/sigstore/sigstore/pkg/signature/kms/aws

replace github.com/sigstore/sigstore => ../../../../

go 1.22.0

require (
	github.com/aws/aws-sdk-go v1.55.5
	github.com/aws/aws-sdk-go-v2 v1.32.6
	github.com/aws/aws-sdk-go-v2/config v1.28.6
	github.com/aws/aws-sdk-go-v2/service/kms v1.37.7
	github.com/jellydator/ttlcache/v3 v3.3.0
	github.com/sigstore/sigstore v1.6.4
	github.com/stretchr/testify v1.10.0
)

require (
	github.com/aws/aws-sdk-go-v2/credentials v1.17.47 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.21 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.25 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.25 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.24.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.28.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.2 // indirect
	github.com/aws/smithy-go v1.22.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-jose/go-jose/v4 v4.0.2 // indirect
	github.com/google/go-containerregistry v0.20.2 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/kr/pretty v0.2.1 // indirect
	github.com/letsencrypt/boulder v0.0.0-20240620165639-de9c06129bec // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.8.0 // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399 // indirect
	golang.org/x/crypto v0.29.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.27.0 // indirect
	golang.org/x/term v0.26.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
