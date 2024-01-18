import binascii
from typing import Union, Optional

from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, EllipticCurvePublicKey, \
    _CURVE_TYPES as EC_CURVE_TYPES
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
        attr_val = priv_key_attrs[attr_id]
        check_result = attr_val == expected_val
        check_result_txt = 'OK' if check_result else 'FAILED'

        attr_hex = hex(attr_id)
        attr_val_txt = attr_val.decode('ascii')

        print(f'-> Attestation attribute {attr_hex} = {attr_val_txt}')
        print(f'{check_result_txt} - {description}')

        if not check_result:
            raise RuntimeError(f"Check failed: {description}")

    print()


def hsm_get_key_public_numbers(priv_key_attrs: dict, curve_name: Optional[str]) -> Union[RSAPublicNumbers, EllipticCurvePublicNumbers]:
    """
    Get public parameters of the key based on the HSM attributes from the attest.
    """

    key_type = priv_key_attrs[OBJ_ATTR_KEY_TYPE]

    if key_type == b'00':
        if curve_name:
            raise RuntimeError("EC curve name was provided but the key is an RSA key.")

        att_n = int(priv_key_attrs[OBJ_ATTR_MODULUS].decode('ascii'), 16)
        att_e = int(priv_key_attrs[OBJ_ATTR_PUBLIC_EXPONENT].decode('ascii'), 16)

        return RSAPublicNumbers(e=att_e, n=att_n)
    elif key_type == b'03':
        if not curve_name:
            raise RuntimeError("No curve name was provided, although the key is an EC key.")

        if curve_name not in EC_CURVE_TYPES:
            supported_curve_names = ', '.join(list(EC_CURVE_TYPES.keys()))
            raise RuntimeError("Unsupported curve name, must be one of: " + supported_curve_names)

        curve_class = EC_CURVE_TYPES[curve_name]

        pub_key = binascii.unhexlify(priv_key_attrs[OBJ_ATTR_MODULUS].decode('ascii'))
        return EllipticCurvePublicKey.from_encoded_point(curve=curve_class(), data=pub_key).public_numbers()

    raise RuntimeError(f"Unsupported subclass key type: {key_type}")


def hsm_get_public_key_pem(hsm_pub_numbers: RSAPublicNumbers) -> str:
    return hsm_pub_numbers.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode('ascii')


def hsm_get_public_key_der(hsm_pub_numbers: RSAPublicNumbers) -> bytes:
    return hsm_pub_numbers.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
