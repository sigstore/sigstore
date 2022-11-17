module github.com/sigstore/sigstore

go 1.18

require (
	cloud.google.com/go/kms v1.6.0
	github.com/Azure/azure-sdk-for-go v67.1.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.28
	github.com/Azure/go-autorest/autorest/to v0.4.0
	github.com/aws/aws-sdk-go v1.44.138
	github.com/aws/aws-sdk-go-v2 v1.17.1
	github.com/aws/aws-sdk-go-v2/config v1.18.1
	github.com/aws/aws-sdk-go-v2/service/kms v1.18.17
	github.com/coreos/go-oidc/v3 v3.4.0
	github.com/go-rod/rod v0.112.0
	github.com/go-test/deep v1.0.8
	github.com/google/go-cmp v0.5.9
	github.com/google/go-containerregistry v0.12.1
	github.com/hashicorp/vault/api v1.8.2
	github.com/jellydator/ttlcache/v2 v2.11.1
	github.com/letsencrypt/boulder v0.0.0-20221109233200-85aa52084eaf
	github.com/mitchellh/go-homedir v1.1.0
	github.com/pkg/browser v0.0.0-20210911075715-681adbf594b8
	github.com/secure-systems-lab/go-securesystemslib v0.4.0
	github.com/segmentio/ksuid v1.0.4
	github.com/skratchdot/open-golang v0.0.0-20200116055534-eef842397966
	github.com/stretchr/testify v1.8.1
	github.com/theupdateframework/go-tuf v0.5.2-0.20220930112810-3890c1e7ace4
	golang.org/x/crypto v0.2.0
	golang.org/x/oauth2 v0.2.0
	golang.org/x/term v0.2.0
	google.golang.org/api v0.103.0
	google.golang.org/genproto v0.0.0-20221111202108-142d8a6fa32e
	google.golang.org/protobuf v1.28.1
	gopkg.in/square/go-jose.v2 v2.6.0
)

require (
	cloud.google.com/go/compute v1.12.1 // indirect
	cloud.google.com/go/compute/metadata v0.2.1 // indirect
	cloud.google.com/go/iam v0.7.0 // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.21 // indirect
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.11 // indirect
	github.com/Azure/go-autorest/autorest/azure/cli v0.4.6 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.3.1 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/armon/go-metrics v0.4.1 // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.13.1 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.12.19 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.25 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.19 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.26 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.11.25 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.13.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.17.3 // indirect
	github.com/aws/smithy-go v1.13.4 // indirect
	github.com/cenkalti/backoff/v3 v3.2.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dimchansky/utfbom v1.1.1 // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/golang-jwt/jwt/v4 v4.4.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.0 // indirect
	github.com/googleapis/gax-go/v2 v2.7.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-hclog v1.3.1 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-plugin v1.4.6 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.1 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-secure-stdlib/mlock v0.1.2 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.7 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.2 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/hashicorp/go-version v1.6.0 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hashicorp/vault/sdk v0.6.1 // indirect
	github.com/hashicorp/yamux v0.1.1 // indirect
	github.com/jhump/protoreflect v1.14.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.16 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-testing-interface v1.14.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/oklog/run v1.1.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/pierrec/lz4 v2.6.1+incompatible // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/syndtr/goleveldb v1.0.1-0.20220721030215-126854af5e6d // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399 // indirect
	github.com/ysmood/goob v0.4.0 // indirect
	github.com/ysmood/gson v0.7.2 // indirect
	github.com/ysmood/leakless v0.8.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	golang.org/x/net v0.2.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.2.0 // indirect
	golang.org/x/text v0.4.0 // indirect
	golang.org/x/time v0.2.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/grpc v1.50.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
