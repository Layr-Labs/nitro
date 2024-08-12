import sys
import struct
import hashlib

BLS_MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513
BYTES_PER_FIELD_ELEMENT = 32
FIELD_ELEMENTS_PER_BLOB = 4096
KZG_ENDIANNESS='big'


def write_data_to_file(filename, preimages):
    with open(filename, 'wb') as file:
        for preimage in preimages:
            preimage_type, data = preimage
            file.write(struct.pack('B', preimage_type))
            file.write(struct.pack('<Q', len(data)))
            file.write(data)

def kzg_test_data():
    data = []
    for i in range(FIELD_ELEMENTS_PER_BLOB):
        h = hashlib.sha512(bytes(str(i), encoding='utf8')).digest()
        scalar = int.from_bytes(h, byteorder=KZG_ENDIANNESS) % BLS_MODULUS
        h = scalar.to_bytes(BYTES_PER_FIELD_ELEMENT, byteorder=KZG_ENDIANNESS)
        data.extend(h)
    return bytes(data)

def kzg_bn254_2mb_test_data():
    # load 2MB padded blob from file
    # 01bc9203a3f91276750f5fdc7241e7b09c94ae58f7f189aa292858a040bd7858
    with open("scripts/eigenda_large_blob.txt", "r") as file:
        data = file.read().strip()
        # decode hex string to bytes
        return bytes.fromhex(data[2:])

def kzg_bn254_128b_test_data():
    # 00bca02094eb78126a517b206a88c73cfa9ec6f704c7030d18212cace820f025
    data = bytes([0 ,0 ,0 ,0 ,0 ,64 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,48 ,48 ,98 ,99 ,97 ,48 ,50 ,48 ,57 ,52 ,101 ,98 ,55 ,56 ,49 ,50 ,54 ,97 ,53 ,49 ,55 ,98 ,50 ,48 ,54 ,97 ,56 ,56 ,99 ,55 ,51 ,0 ,99 ,102 ,97 ,57 ,101 ,99 ,54 ,102 ,55 ,48 ,52 ,99 ,55 ,48 ,51 ,48 ,100 ,49 ,56 ,50 ,49 ,50 ,99 ,97 ,99 ,101 ,56 ,50 ,48 ,102 ,48 ,0 ,50 ,53 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0])

    return data

if len(sys.argv) < 2:
    print("Usage: python3 create-test-preimages.py <filename>")
    sys.exit(1)

filename = sys.argv[1]

preimages = [
    (0, b'hello world'),
    (1, b'hello world'),
    (2, kzg_test_data()),
    (3, kzg_bn254_2mb_test_data()),
    (3, kzg_bn254_128b_test_data()),
]

write_data_to_file(filename, preimages)
