module sigstore-kms-localkms

go 1.24.0

toolchain go1.24.5

replace github.com/sigstore/sigstore => ../../..

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/sigstore/sigstore v0.0.0-00010101000000-000000000000
)

require (
	github.com/go-jose/go-jose/v4 v4.1.0 // indirect
	github.com/google/go-containerregistry v0.20.6 // indirect
	github.com/letsencrypt/boulder v0.20250721.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.9.0 // indirect
	github.com/sigstore/protobuf-specs v0.4.3 // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/term v0.33.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250519155744-55703ea1f237 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250519155744-55703ea1f237 // indirect
	google.golang.org/grpc v1.72.1 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)
