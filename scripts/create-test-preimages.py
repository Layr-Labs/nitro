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

def eigen_test_data():    
    # the value we are returning is the same string that is returned by the old eigen_test_data but encoded in the style the high level eigenDA client would
    # 00bca02094eb78126a517b206a88c73cfa9ec6f704c7030d18212cace820f025
    data = bytes([
    158, 2, 210, 200, 222, 109, 75, 254, 172, 35, 198, 167, 91, 2, 162, 61, 166, 121, 207, 233, 35, 39, 167, 255, 149, 79, 85, 231, 66, 2, 108, 125, 183, 44, 68, 125, 100, 9, 40, 88, 244, 18, 229, 195, 81, 229, 21, 139, 162, 90, 20, 185, 37, 42, 18, 51, 27, 153, 135, 250, 189, 197, 69, 153, 3, 113, 39, 19, 135, 189, 26, 71, 235, 41, 30, 143, 153, 141, 133, 7, 49, 91, 167, 148, 196, 8, 54, 147, 210, 207, 174, 244, 154, 158, 87, 177, 249, 21, 73, 27, 197, 56, 254, 167, 215, 132, 34, 231, 237, 79, 180, 232, 27, 164, 17, 91, 237, 55, 218, 145, 96, 213, 55, 45, 175, 21, 223, 135])

    return data

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
