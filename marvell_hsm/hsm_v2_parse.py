"""
Script for parsing a version 2 attestation file.
Originally authored by Marvell
https://www.marvell.com/products/security-solutions/nitrox-hs-adapters/software-key-attestation.html

Contains custom unofficial modifications introduced for the purpose of this project.
"""
import binascii
import gzip
import hashlib
import os
import struct

# Attestation structure is big endian.
# The response header is composed of the following:
# 1. Response code.
# 2. Request flags. These are set to include both the headers and the attributes
#    in the attestation.
# 3. Total size of the attestation.
# 4. Buffer size. The buffer contains the attestation attributes.
RESPONSE_HEADER = '>IIII'
# The info header is composed of the following:
# 1. Object version.
# 2. Request flags. These are set to include both the headers and the attributes
#    in the attestation.
# 3. Offset to the attributes of the first key.
# 4. Offset to the attributes of the second key.
INFO_HEADER = '>HHHH'
# The object header is composed of the handle, attribute count, and object size.
OBJ_HEADER = '>III'
# The TLV is composed of the object type and its size.
TLV = '>II'
# The attestation is signed with a 256-byte RSA signature.
SIGNATURE_SIZE = 256


def get_contents_decompress_if_needed(attestation_file):
    print('[#] Loading attestation file: ' + os.path.basename(attestation_file))

    with open(attestation_file, 'rb') as f:
        raw_file = f.read()
        file_sha256 = hashlib.sha256(raw_file).hexdigest()
        file_sha512 = hashlib.sha512(raw_file).hexdigest()

        print(f'-> Attestation file SHA-256:')
        print(file_sha256)

    print()

    try:
        return gzip.decompress(raw_file)
    except OSError:
        return raw_file


def parse_headers(attestation):
    _, _, totalsize, bufsize = struct.unpack_from(RESPONSE_HEADER, attestation, 0)
    attribute_offset = totalsize - (bufsize + SIGNATURE_SIZE)
    attest_data = attestation[attribute_offset:]
    _, _, offset1, offset2 = struct.unpack_from(INFO_HEADER, attest_data, 0)
    return attest_data, offset1, offset2


def parse(attest_data):
    _, attr_count, _ = struct.unpack_from(OBJ_HEADER, attest_data, 0)
    obj_header_size = struct.calcsize(OBJ_HEADER)
    attest_data = attest_data[obj_header_size:]
    attributes = {}
    while attr_count > 0:
        # Parse each Attribute.
        attr_type, attr_len = struct.unpack_from(TLV, attest_data, 0)
        attest_data = attest_data[struct.calcsize(TLV):]
        attributes[attr_type] = binascii.hexlify(attest_data[:attr_len])
        attr_count -= 1
        attest_data = attest_data[attr_len:]
    return attributes


def print_attributes(attributes):
    known_names = hsm_attr_list._KNOWN_KEYS
    attr_map = {}

    for known_name in known_names:
        attr_id = getattr(hsm_attr_list, known_name)
        attr_map[attr_id] = known_name

    for attr in sorted(attributes):
        attr_name = hex(attr)

        if attr in attr_map:
            attr_name = attr_map[attr]

        print('%s: %s' % (attr_name, attributes[attr]))


def get_priv_key_attrs(attest_file_name):
    attestation = get_contents_decompress_if_needed(attest_file_name)
    attest_data, offset_pub, offset_priv = parse_headers(attestation)

    if offset_priv <= 0:
        raise RuntimeError("Expected to find two keys (public and private) in the attest.")

    return parse(attest_data[offset_priv:])
