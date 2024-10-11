module fakekmsplugin

go 1.23.0

replace github.com/sigstore/sigstore => ../../..

replace github.com/sigstore/sigstore/pkg/signature/kms/kmsgoplugin => ../../../pkg/signature/kms/kmsgoplugin

require (
	github.com/hashicorp/go-hclog v1.6.3
	github.com/hashicorp/go-plugin v1.6.1
	github.com/sigstore/sigstore v0.0.0-00010101000000-000000000000
	github.com/sigstore/sigstore/pkg/signature/kms/kmsgoplugin v0.0.0-00010101000000-000000000000
)

require (
	github.com/fatih/color v1.13.0 // indirect
	github.com/go-jose/go-jose/v4 v4.0.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-containerregistry v0.20.2 // indirect
	github.com/hashicorp/yamux v0.1.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/letsencrypt/boulder v0.0.0-20240620165639-de9c06129bec // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mitchellh/go-testing-interface v0.0.0-20171004221916-a61a99592b77 // indirect
	github.com/oklog/run v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.8.0 // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399 // indirect
	golang.org/x/crypto v0.25.0 // indirect
	golang.org/x/net v0.27.0 // indirect
	golang.org/x/sys v0.22.0 // indirect
	golang.org/x/term v0.22.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240520151616-dc85e6b867a5 // indirect
	google.golang.org/grpc v1.64.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
