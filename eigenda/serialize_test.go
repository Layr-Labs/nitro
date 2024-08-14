package eigenda

import "testing"


func Test_EncodeDecodeBlob(t *testing.T) {
	rawBlob := []byte("optimistic nihilism")

	encodedBlob, err := GenericEncodeBlob(rawBlob)
	if err != nil {
		t.Fatalf("failed to encode blob: %v", err)
	}

	decodedBlob, err := GenericDecodeBlob(encodedBlob)
	if err != nil {
		t.Fatalf("failed to decode blob: %v", err)
	}

	if string(decodedBlob) != string(rawBlob) {
		t.Fatalf("decoded blob does not match raw blob")
	}
}