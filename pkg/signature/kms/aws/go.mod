module github.com/sigstore/sigstore/pkg/signature/kms/aws

replace github.com/sigstore/sigstore => ../../../../

go 1.27

require (
	github.com/aws/aws-sdk-go-v2 v1.47.7
	github.com/aws/aws-sdk-go-v2/config v1.33.15
	github.com/aws/aws-sdk-go-v2/service/kms v1.62.4
	github.com/jellydator/ttlcache/v3 v3.4.1
	github.com/sigstore/sigstore v1.6.4
	github.com/stretchr/testify v1.12.1
)

require (
	github.com/aws/aws-sdk-go-v2/credentials v1.20.15 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.7 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.10 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.10 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.24 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.12.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.39.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.44.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.8 // indirect
	github.com/aws/smithy-go v1.28.8 // indirect
	github.com/google/go-containerregistry v0.22.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.11.1 // indirect
	github.com/sigstore/protobuf-specs v0.5.2 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/term v0.45.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260727163830-6c54dddc4772 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

retract v1.10.1 // License issue
