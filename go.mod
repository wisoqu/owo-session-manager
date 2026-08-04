module owocloud/session-manager

go 1.25.0

require (
	github.com/refraction-networking/utls v1.6.7
	github.com/xtaci/smux v1.5.57
	golang.org/x/crypto v0.24.0
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	golang.org/x/sys v0.21.0 // indirect
)

replace golang.org/x/crypto v0.24.0 => github.com/golang/crypto v0.24.0

replace golang.org/x/sys v0.21.0 => github.com/golang/sys v0.21.0
