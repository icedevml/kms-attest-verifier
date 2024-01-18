import binascii
from typing import Union

from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, EllipticCurvePublicKey, \
    SECP256K1
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

from marvell_hsm.hsm_attr_list import OBJ_ATTR_PRIVATE, OBJ_ATTR_EXTRACTABLE, OBJ_ATTR_LOCAL, \
    OBJ_ATTR_NEVER_EXTRACTABLE, \
    OBJ_ATTR_MODULUS, OBJ_ATTR_PUBLIC_EXPONENT, OBJ_ATTR_SENSITIVE, OBJ_ATTR_KEY_TYPE


def hsm_check_priv_key_attrs(priv_key_attrs: dict) -> None:
    """
    Verify whether the private key has correct attributes set on the HSM.
    """

    print('[#] Check attributes in the attestation file')

    ASSERTIONS = [
        [OBJ_ATTR_PRIVATE, b'01', 'Key is a private key'],
        [OBJ_ATTR_EXTRACTABLE, b'00', 'Key is not extractable'],
        [OBJ_ATTR_NEVER_EXTRACTABLE, b'01', 'Key is marked as never extractable'],
        [OBJ_ATTR_LOCAL, b'01', 'Key was locally generated'],
        [OBJ_ATTR_SENSITIVE, b'01', 'Key was generated on HSM'],
    ]

    for assertion in ASSERTIONS:
        attr_id, expected_val, description = assertion
        check_result = priv_key_attrs[attr_id] == expected_val
        check_result_txt = 'OK' if check_result else 'FAILED'
        print(f'{check_result_txt} - {description}')

        if not check_result:
            raise RuntimeError(f"Check failed: {description}")

    print()


def hsm_get_key_public_numbers(priv_key_attrs: dict) -> Union[RSAPublicNumbers, EllipticCurvePublicNumbers]:
    """
    Get public parameters of the key based on the HSM attributes from the attest.
    """

    key_type = priv_key_attrs[OBJ_ATTR_KEY_TYPE]

    if key_type == b'00':
        att_n = int(priv_key_attrs[OBJ_ATTR_MODULUS].decode('ascii'), 16)
        att_e = int(priv_key_attrs[OBJ_ATTR_PUBLIC_EXPONENT].decode('ascii'), 16)

        return RSAPublicNumbers(e=att_e, n=att_n)
    elif key_type == b'03':
        pub_key = binascii.unhexlify(priv_key_attrs[OBJ_ATTR_MODULUS].decode('ascii'))
        return EllipticCurvePublicKey.from_encoded_point(curve=SECP256K1(), data=pub_key).public_numbers()

    raise RuntimeError(f"Unsupported subclass key type: {key_type}")


def hsm_get_public_key_pem(hsm_pub_numbers: RSAPublicNumbers) -> str:
    return hsm_pub_numbers.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode('ascii')
