package eigenda

import (
	"encoding/hex"
	"testing"
)

func TestParseSequencerMsg(t *testing.T) {
	calldataString := "4a1af08e000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000003600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000004500000000000000000000000000000000000000000000000000000000000001a400000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002400000000000000000000000000000000000000000000000000000000000000060cc590258405c5976efd9eb8256a9fc53648be8c03ea50e64cecc6fe506c9b35e0000000000000000000000000000000000000000000000000000000000000390cc590258405c5976efd9eb8256a9fc53648be8c03ea50e64cecc6fe506c9b35e000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000003900000000000000000000000000000000000000000000000000000000000000002010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000026090000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a5fe184d9556ebdf6d4e600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000201000000000000000000000000000000000000000000000000000000000000000945625d31a92d4ab0543870a119b5908375e01e029c480c4bb083a27d17693929d7388444393702012a75edf6ff54037085f4df5e9a6884d781f59aa84a0a430000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000001d000000000000000000000000000000000000000000000000000000000000001e000000000000000000000000000000000000000000000000000000000000012c"

	calldata, err := hex.DecodeString(calldataString)
	if err != nil {
		t.Fatalf("Failed to decode calldata: %v", err)
	}

	expected := &EigenDABlobInfo{
		// BatchHeader content for hashing
		BlobVerificationProof: BlobVerificationProof{
			BatchID: 69,
		},
	}

	// Call the function with the mock calldata
	result, err := ParseSequencerMsg(calldata)
	if err != nil {
		t.Fatalf("ParseSequencerMsg returned an error: %v", err)
	}

	// TODO: Extend the test to cover all fields
	if result.BlobVerificationProof.BatchID != expected.BlobVerificationProof.BatchID {
		t.Errorf("BlobIndex was incorrect, got: %v, want: %v", result.BlobVerificationProof.BatchID, expected.BlobVerificationProof.BatchID)
	}

}
