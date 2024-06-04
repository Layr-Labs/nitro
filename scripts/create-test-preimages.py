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
    12, 74, 134, 141, 159, 142, 12, 228, 147, 176, 42, 148, 17, 187, 240, 48, 98, 179, 158, 173, 119, 72, 129, 73, 181, 94, 239, 1, 22, 164, 231, 89, 
    45, 148, 221, 13, 66, 188, 31, 31, 18, 90, 120, 195, 53, 74, 121, 91, 29, 163, 78, 174, 81, 239, 152, 253, 188, 242, 52, 132, 164, 53, 20, 26, 
    36, 75, 123, 21, 222, 118, 68, 224, 87, 187, 179, 60, 161, 97, 0, 70, 93, 178, 98, 55, 27, 137, 136, 121, 63, 52, 185, 46, 242, 115, 75, 192, 
    2, 157, 190, 53, 1, 226, 207, 111, 114, 218, 52, 217, 26, 155, 70, 232, 114, 94, 128, 254, 14, 177, 62, 97, 214, 62, 14, 115, 50, 178, 184, 207
    ])

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
