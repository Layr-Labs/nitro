package daprovider

import "testing"

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
