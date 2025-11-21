// Copyright 2021-2022, Offchain Labs, Inc.
// For license information, see https://github.com/OffchainLabs/nitro/blob/master/LICENSE.md

package arbutil

type PreimageType uint8

// These values must be kept in sync with `arbitrator/arbutil/src/types.rs`,
// and the if statement in `contracts/src/osp/OneStepProverHostIo.sol` (search for "UNKNOWN_PREIMAGE_TYPE").
const (
	Keccak256PreimageType     PreimageType = 0
	Sha2_256PreimageType      PreimageType = 1
	EthVersionedHashPreimageType PreimageType = 2
	// EigenDA keeps value 3 (existing deployments depend on this)
	// DACertificate moved to 4 to avoid collision (per PR #128 precedent)
	// Related: https://github.com/Layr-Labs/nitro/issues/129
	EigenDaPreimageType       PreimageType = 3
	DACertificatePreimageType PreimageType = 4
)
