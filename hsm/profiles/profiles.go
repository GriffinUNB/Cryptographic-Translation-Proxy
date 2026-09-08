// Package profiles provides embedded certificate profile templates.
//
// These profiles define certificate enrollment policies and are embedded
// in the binary for convenience. Users can also copy and customize them.
package profiles

import "embed"

// FS contains all embedded profile YAML files.
// Profiles are organized in subdirectories:
//   - ec/          - EC (ECDSA/ECDH) algorithm profiles
//   - rsa/         - RSA algorithm profiles (legacy)
//   - ml/          - Post-quantum profiles (ML-DSA + ML-KEM)
//   - slh/         - Hash-based signature profiles (SLH-DSA)
//   - hybrid/      - Hybrid classical + PQC profiles
//   - catalyst/    - Dual signature (legacy compatibility)
//   - composite/   - IETF composite signature
//   - eidas/       - eIDAS qualified certificate profiles
//
//go:embed all:ec all:rsa all:ml all:slh all:hybrid all:eidas
var FS embed.FS
