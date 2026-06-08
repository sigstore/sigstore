module github.com/sigstore/sigstore/pkg/signature/kms/aws

replace github.com/sigstore/sigstore => ../../../../

go 1.25.0

require (
	github.com/aws/aws-sdk-go-v2 v1.41.12
	github.com/aws/aws-sdk-go-v2/config v1.32.21
	github.com/aws/aws-sdk-go-v2/service/kms v1.53.3
	github.com/jellydator/ttlcache/v3 v3.4.0
	github.com/sigstore/sigstore v1.6.4
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/aws/aws-sdk-go-v2/credentials v1.19.20 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.26 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.28 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.28 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.27 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.26 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.1.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.31.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.36.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.43.0 // indirect
	github.com/aws/smithy-go v1.27.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/go-containerregistry v0.21.6 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.11.0 // indirect
	github.com/sigstore/protobuf-specs v0.5.1 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/term v0.43.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

retract v1.10.1 // License issue
