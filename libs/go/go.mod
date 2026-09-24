// Shared Go building blocks: Vault client, mTLS identity and RPC authorization.
module jarvis.internal/libs/go

go 1.27

replace jarvis.internal/gen/go => ../../gen/go

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	google.golang.org/grpc v1.84.0
	jarvis.internal/gen/go v0.0.0-00010101000000-000000000000
)

require (
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260706201446-f0a921348800 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
