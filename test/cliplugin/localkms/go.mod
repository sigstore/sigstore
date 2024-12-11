module sigstore-kms-localkms

go 1.23.2

// replace github.com/sigstore/sigstore => ../../..

replace github.com/sigstore/sigstore/pkg/signature/kms/cliplugin => ../../../pkg/signature/kms/cliplugin

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/sigstore/sigstore v1.8.10
	github.com/sigstore/sigstore/pkg/signature/kms/cliplugin v0.0.0-00010101000000-000000000000
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-jose/go-jose/v4 v4.0.2 // indirect
	github.com/google/go-containerregistry v0.20.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/letsencrypt/boulder v0.0.0-20240620165639-de9c06129bec // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.8.0 // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399 // indirect
	golang.org/x/crypto v0.29.0 // indirect
	golang.org/x/sys v0.27.0 // indirect
	golang.org/x/term v0.26.0 // indirect
	google.golang.org/grpc v1.67.1 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
