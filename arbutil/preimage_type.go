// Copyright 2021-2022, Offchain Labs, Inc.
// For license information, see https://github.com/OffchainLabs/nitro/blob/master/LICENSE.md

package arbutil

type PreimageType uint8

// These values must be kept in sync with `arbitrator/arbutil/src/types.rs`,
// and the if statement in `contracts/src/osp/OneStepProverHostIo.sol` (search for "UNKNOWN_PREIMAGE_TYPE").
const (
	Keccak256PreimageType        PreimageType = 0
	Sha2_256PreimageType                      = 1
	EthVersionedHashPreimageType              = 2
	DACertificatePreimageType                 = 3

	EigenDaPreimageType = 69
)
