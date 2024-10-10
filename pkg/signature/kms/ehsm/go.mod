module github.com/sigstore/sigstore/pkg/signature/kms/ehsm

replace github.com/sigstore/sigstore => ../../../../

go 1.20

require (
	github.com/intel/ehsm/sdk/go v0.4.0
	github.com/jellydator/ttlcache/v3 v3.0.1
	github.com/sigstore/sigstore v1.7.2
	github.com/stretchr/testify v1.8.4
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/go-containerregistry v0.16.1 // indirect
	github.com/iancoleman/orderedmap v0.3.0 // indirect
	github.com/letsencrypt/boulder v0.0.0-20230810172437-1962d8687c30 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/theupdateframework/go-tuf v0.6.1 // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399 // indirect
	golang.org/x/crypto v0.12.0 // indirect
	golang.org/x/sync v0.3.0 // indirect
	golang.org/x/sys v0.11.0 // indirect
	golang.org/x/term v0.11.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230530153820-e85fd2cbaebc // indirect
	google.golang.org/grpc v1.56.0 // indirect
	gopkg.in/go-jose/go-jose.v2 v2.6.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
