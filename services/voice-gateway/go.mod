module jarvis.internal/voice-gateway

go 1.27

// Generated protobuf code lives in this repo; resolve it locally even
// outside the Go workspace (e.g. `go mod tidy`).
replace (
	jarvis.internal/gen/go => ../../gen/go
	jarvis.internal/libs/go => ../../libs/go
)

require (
	github.com/coder/websocket v1.8.15
	github.com/google/uuid v1.6.0
	github.com/prometheus/client_golang v1.24.1
	google.golang.org/grpc v1.84.0
	google.golang.org/protobuf v1.36.12
	jarvis.internal/gen/go v0.0.0-00010101000000-000000000000
	jarvis.internal/libs/go v0.0.0-00010101000000-000000000000
)

require (
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.70.1 // indirect
	github.com/prometheus/procfs v0.21.1 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260706201446-f0a921348800 // indirect
)
