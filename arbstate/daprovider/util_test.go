package daprovider

import (
	"testing"
)

func Test_EigenDAHeaderByte(t *testing.T) {
	if IsL1AuthenticatedMessageHeaderByte(EigenDAMessageHeaderFlag) {
		t.Error("Expected EigenDAMessageHeaderFlag to not be a valid L1 authenticated message header byte")
	}

	if IsDASMessageHeaderByte(EigenDAMessageHeaderFlag) {
		t.Error("Expected EigenDAMessageHeaderFlag to not be a valid DAS message header byte")
	}

	if IsTreeDASMessageHeaderByte(EigenDAMessageHeaderFlag) {
		t.Error("Expected EigenDAMessageHeaderFlag to not be a valid Tree DAS message header byte")
	}

	if IsZeroheavyEncodedHeaderByte(EigenDAMessageHeaderFlag) {
		t.Error("Expected EigenDAMessageHeaderFlag to not be a valid Zeroheavy encoded header byte")
	}

	if IsBlobHashesHeaderByte(EigenDAMessageHeaderFlag) {
		t.Error("Expected EigenDAMessageHeaderFlag to not be a valid Blob hashes header byte")
	}

	if IsBrotliMessageHeaderByte(EigenDAMessageHeaderFlag) {
		t.Error("Expected EigenDAMessageHeaderFlag to not be a valid Brotli message header byte")
	}
}

func Test_HeaderByteCheck(t *testing.T) {
	if !IsL1AuthenticatedMessageHeaderByte(L1AuthenticatedMessageHeaderFlag) {
		t.Error("Expected L1AuthenticatedMessageHeaderFlag to be a valid L1 authenticated message header byte")
	}

	if !IsDASMessageHeaderByte(DASMessageHeaderFlag) {
		t.Error("Expected DASMessageHeaderFlag to be a valid DAS message header byte")
	}

	if !IsTreeDASMessageHeaderByte(TreeDASMessageHeaderFlag) {
		t.Error("Expected TreeDASMessageHeaderFlag to be a valid Tree DAS message header byte")
	}

	if !IsZeroheavyEncodedHeaderByte(ZeroheavyMessageHeaderFlag) {
		t.Error("Expected ZeroheavyMessageHeaderFlag to be a valid Zeroheavy encoded header byte")
	}

	if !IsBlobHashesHeaderByte(BlobHashesHeaderFlag) {
		t.Error("Expected BlobHashesHeaderFlag to be a valid Blob hashes header byte")
	}

	if !IsBrotliMessageHeaderByte(BrotliMessageHeaderByte) {
		t.Error("Expected BrotliMessageHeaderByte to be a valid Brotli message header byte")
	}

	if !IsEigenDAMessageHeaderByte(EigenDAMessageHeaderFlag) {
		t.Error("Expected EigenDAMessageHeaderFlag to be a valid EigenDA message header byte")
	}
}
