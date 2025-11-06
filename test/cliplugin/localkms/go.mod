module sigstore-kms-localkms

go 1.24.0

toolchain go1.24.5

replace github.com/sigstore/sigstore => ../../..

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/sigstore/sigstore v0.0.0-00010101000000-000000000000
)

require (
	github.com/google/go-containerregistry v0.20.6 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.9.1 // indirect
	github.com/sigstore/protobuf-specs v0.5.0 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/term v0.36.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250519155744-55703ea1f237 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)
