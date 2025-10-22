package eigenda

import (
	"bytes"

	"github.com/ethereum/go-ethereum/accounts/abi"
	gethcommon "github.com/ethereum/go-ethereum/common"
)

var certDecodeABI abi.ABI

// HistoricalEigenDAWasmRoots is a mapping of historical consensus artifacts (i.e, prover machine and binary)
// that use EigenDAPreimageType=3
var HistoricalEigenDAWasmRoots map[gethcommon.Hash]interface{}

func init() {
	HistoricalEigenDAWasmRoots =
		map[gethcommon.Hash]interface{}{
			gethcommon.HexToHash("0x2c9a9d645ae56304c483709fc710a58a0935ed43893179fe4b275e1400503ea7"): nil, // consensus-eigenda-v40
			gethcommon.HexToHash("0x39a7b951167ada11dc7c81f1707fb06e6710ca8b915b2f49e03c130bf7cd53b1"): nil, // consensus-eigenda-v32.3
			gethcommon.HexToHash("0xc723bd1be9fc564796bd8ce5c158c8b2f55d34afb38303a9fb6a8f0fda376edb"): nil, // consensus-eigenda-v32.2
			gethcommon.HexToHash("0x04a297cdd13254c4c6c26388915d416286daf22f3a20e3ebee10400a3129dd17"): nil, // consensus-eigenda-v32.1
		}

	var err error
	certDecodeRawABI := `[
		{
			"type": "function",
			"name": "decodeCert",
			"inputs": [
				{
					"name": "cert",
					"type": "tuple",
					"internalType": "struct ISequencerInbox.DACert",
					"components": [
						{
							"name": "blobVerificationProof",
							"type": "tuple",
							"internalType": "struct EigenDARollupUtils.BlobVerificationProof",
							"components": [
								{
									"name": "batchId",
									"type": "uint32",
									"internalType": "uint32"
								},
								{
									"name": "blobIndex",
									"type": "uint32",
									"internalType": "uint32"
								},
								{
									"name": "batchMetadata",
									"type": "tuple",
									"internalType": "struct IEigenDAServiceManager.BatchMetadata",
									"components": [
										{
											"name": "batchHeader",
											"type": "tuple",
											"internalType": "struct IEigenDAServiceManager.BatchHeader",
											"components": [
												{
													"name": "blobHeadersRoot",
													"type": "bytes32",
													"internalType": "bytes32"
												},
												{
													"name": "quorumNumbers",
													"type": "bytes",
													"internalType": "bytes"
												},
												{
													"name": "signedStakeForQuorums",
													"type": "bytes",
													"internalType": "bytes"
												},
												{
													"name": "referenceBlockNumber",
													"type": "uint32",
													"internalType": "uint32"
												}
											]
										},
										{
											"name": "signatoryRecordHash",
											"type": "bytes32",
											"internalType": "bytes32"
										},
										{
											"name": "confirmationBlockNumber",
											"type": "uint32",
											"internalType": "uint32"
										}
									]
								},
								{
									"name": "inclusionProof",
									"type": "bytes",
									"internalType": "bytes"
								},
								{
									"name": "quorumIndices",
									"type": "bytes",
									"internalType": "bytes"
								}
							]
						},
						{
							"name": "blobHeader",
							"type": "tuple",
							"internalType": "struct IEigenDAServiceManager.BlobHeader",
							"components": [
								{
									"name": "commitment",
									"type": "tuple",
									"internalType": "struct BN254.G1Point",
									"components": [
										{
											"name": "X",
											"type": "uint256",
											"internalType": "uint256"
										},
										{
											"name": "Y",
											"type": "uint256",
											"internalType": "uint256"
										}
									]
								},
								{
									"name": "dataLength",
									"type": "uint32",
									"internalType": "uint32"
								},
								{
									"name": "quorumBlobParams",
									"type": "tuple[]",
									"internalType": "struct IEigenDAServiceManager.QuorumBlobParam[]",
									"components": [
										{
											"name": "quorumNumber",
											"type": "uint8",
											"internalType": "uint8"
										},
										{
											"name": "adversaryThresholdPercentage",
											"type": "uint8",
											"internalType": "uint8"
										},
										{
											"name": "confirmationThresholdPercentage",
											"type": "uint8",
											"internalType": "uint8"
										},
										{
											"name": "chunkLength",
											"type": "uint32",
											"internalType": "uint32"
										}
									]
								}
							]
						}
					]
				}
			],
			"outputs": [],
			"stateMutability": "nonpayable"
		}
	]
	`
	certDecodeABI, err = abi.JSON(bytes.NewReader([]byte(certDecodeRawABI)))
	if err != nil {
		panic(err)
	}
}
