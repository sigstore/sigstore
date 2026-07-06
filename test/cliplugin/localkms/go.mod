module sigstore-kms-localkms

go 1.25.0

replace github.com/sigstore/sigstore => ../../..

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/sigstore/sigstore v0.0.0-00010101000000-000000000000
)

require (
	github.com/google/go-containerregistry v0.21.7 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.11.0 // indirect
	github.com/sigstore/protobuf-specs v0.5.1 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/term v0.43.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
