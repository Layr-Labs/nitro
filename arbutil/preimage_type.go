// Copyright 2021-2022, Offchain Labs, Inc.
// For license information, see https://github.com/OffchainLabs/nitro/blob/master/LICENSE.md

package arbutil

type PreimageType uint8

// These values must be kept in sync with `arbitrator/arbutil/src/types.rs`,
// and the if statement in `contracts/src/osp/OneStepProverHostIo.sol` (search for "UNKNOWN_PREIMAGE_TYPE").
const (
	Keccak256PreimageType PreimageType = iota
	Sha2_256PreimageType
	EthVersionedHashPreimageType
	// TODO(#129): CRITICAL - Preimage type collision with EigenDAHash and DACertificate both using value 3
	// After v3.9.0 rebase, need team decision on resolution:
	//   Option 1: Keep EigenDA=3, move DACertificate=4 (maintains EigenDA compatibility)
	//   Option 2: Move EigenDA=4, DACertificate=3 (aligns with upstream v3.9.0)
	//   Option 3: Move EigenDA=5+ (cleanest separation for future)
	// Impact: Rust types.rs enum, WASM preimage resolution, on-chain verifiers
	EigenDaPreimageType
	DACertificatePreimageType
)
