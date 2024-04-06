import sys
import struct
import hashlib

BLS_MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513
BYTES_PER_FIELD_ELEMENT = 32
FIELD_ELEMENTS_PER_BLOB = 4096
KZG_ENDIANNESS='big'

BN254_BLS_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
EIGENDA_FIELD_ELEMENTS_PER_BLOB = 65536

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

def eigen_test_data():
    data = []
    # generate a 32 byte blob
    for i in range(0, 1):
        bytes_64 = bytearray(hashlib.sha512(bytes(str(i), encoding='utf8')).digest())
        bytes_32 = bytes_64[0:32]

        # 0 padding for 1st byte of 32 byte word
        bytes_32[0] = 0
        data.extend(bytes_32)

    print(bytes(data))
    return bytes(data)

if len(sys.argv) < 2:
    print("Usage: python3 create-test-preimages.py <filename>")
    sys.exit(1)

filename = sys.argv[1]

preimages = [
    (0, b'hello world'),
    (1, b'hello world'),
    (2, kzg_test_data()),
    (3, eigen_test_data())
]

write_data_to_file(filename, preimages)
