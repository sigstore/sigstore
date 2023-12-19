module github.com/sigstore/sigstore/pkg/signature/kms/azure

replace github.com/sigstore/sigstore => ../../../../

go 1.20

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.9.1
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.4.0
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys v1.0.1
	github.com/go-jose/go-jose/v3 v3.0.1
	github.com/google/go-cmp v0.6.0
	github.com/jellydator/ttlcache/v3 v3.1.1
	github.com/sigstore/sigstore v1.6.4
	golang.org/x/crypto v0.17.0
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.5.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/internal v1.0.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.1.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.0.0 // indirect
	github.com/google/go-containerregistry v0.16.1 // indirect
	github.com/google/uuid v1.3.1 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/letsencrypt/boulder v0.0.0-20230907030200-6d76a0f91e1e // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/pkg/browser v0.0.0-20210911075715-681adbf594b8 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.7.0 // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399 // indirect
	golang.org/x/net v0.19.0 // indirect
	golang.org/x/sync v0.3.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/term v0.15.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	gopkg.in/go-jose/go-jose.v2 v2.6.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
