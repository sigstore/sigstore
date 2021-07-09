module github.com/sigstore/sigstore

go 1.16

require (
	cloud.google.com/go v0.81.0
	github.com/ReneKroon/ttlcache/v2 v2.5.0
	github.com/aws/aws-sdk-go v1.38.35
	github.com/coreos/go-oidc/v3 v3.0.0
	github.com/gabriel-vasile/mimetype v1.2.0
	github.com/go-openapi/errors v0.20.0
	github.com/go-openapi/runtime v0.19.29
	github.com/go-openapi/strfmt v0.20.1
	github.com/go-openapi/swag v0.19.15
	github.com/go-openapi/validate v0.20.2
	github.com/go-test/deep v1.0.7
	github.com/google/go-containerregistry v0.4.1
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.6.8 // indirect
	github.com/hashicorp/vault/api v1.1.0
	github.com/hashicorp/vault/sdk v0.2.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/pierrec/lz4 v2.6.0+incompatible // indirect
	github.com/pkg/errors v0.9.1
	github.com/segmentio/ksuid v1.0.3
	github.com/sigstore/rekor v0.2.1-0.20210705133645-dbbbff597bc2
	github.com/skratchdot/open-golang v0.0.0-20200116055534-eef842397966
	github.com/spf13/cobra v1.2.1
	github.com/spf13/viper v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/theupdateframework/go-tuf v0.0.0-20201230183259-aee6270feb55
	golang.org/x/crypto v0.0.0-20210506145944-38f3c27a63bf
	golang.org/x/oauth2 v0.0.0-20210427180440-81ed05c6b58c
	golang.org/x/term v0.0.0-20201210144234-2321bbc49cbf
	google.golang.org/genproto v0.0.0-20210602131652-f16073e35f0c
	google.golang.org/protobuf v1.27.1
	gopkg.in/square/go-jose.v2 v2.5.1
)
