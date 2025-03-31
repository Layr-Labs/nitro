package daprovider

import "testing"

func Test_EigenDAV1HeaderByte(t *testing.T) {
	if IsL1AuthenticatedMessageHeaderByte(EigenDAV1MessageHeader) {
		t.Error("Expected EigenDAV1MessageHeader to not be a valid L1 authenticated message header byte")
	}

	if IsDASMessageHeaderByte(EigenDAV1MessageHeader) {
		t.Error("Expected EigenDAV1MessageHeader to not be a valid DAS message header byte")
	}

	if IsTreeDASMessageHeaderByte(EigenDAV1MessageHeader) {
		t.Error("Expected EigenDAV1MessageHeader to not be a valid Tree DAS message header byte")
	}

	if IsZeroheavyEncodedHeaderByte(EigenDAV1MessageHeader) {
		t.Error("Expected EigenDAV1MessageHeader to not be a valid Zeroheavy encoded header byte")
	}

	if IsBlobHashesHeaderByte(EigenDAV1MessageHeader) {
		t.Error("Expected EigenDAV1MessageHeader to not be a valid Blob hashes header byte")
	}

	if IsBrotliMessageHeaderByte(EigenDAV1MessageHeader) {
		t.Error("Expected EigenDAMessageHeaderFlag to not be a valid Brotli message header byte")
	}
}

func Test_EigenDAV2HeaderByte(t *testing.T) {
	if IsL1AuthenticatedMessageHeaderByte(EigenDAV2MessageHeader) {
		t.Error("Expected EigenDAV2MessageHeader to not be a valid L1 authenticated message header byte")
	}

	if IsDASMessageHeaderByte(EigenDAV2MessageHeader) {
		t.Error("Expected EigenDAV2MessageHeader to not be a valid DAS message header byte")
	}

	if IsTreeDASMessageHeaderByte(EigenDAV2MessageHeader) {
		t.Error("Expected EigenDAV2MessageHeader to not be a valid Tree DAS message header byte")
	}

	if IsZeroheavyEncodedHeaderByte(EigenDAV2MessageHeader) {
		t.Error("Expected EigenDAV2MessageHeader to not be a valid Zeroheavy encoded header byte")
	}

	if IsBlobHashesHeaderByte(EigenDAV2MessageHeader) {
		t.Error("Expected EigenDAV2MessageHeader to not be a valid Blob hashes header byte")
	}

	if IsBrotliMessageHeaderByte(EigenDAV2MessageHeader) {
		t.Error("Expected EigenDAMessageHeaderFlag to not be a valid Brotli message header byte")
	}
}
