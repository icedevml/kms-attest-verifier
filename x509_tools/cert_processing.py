import hashlib
import os

from cryptography import x509
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.x509 import Certificate


def cert_get_key_public_numbers(cert: Certificate) -> RSAPublicNumbers:
    """
    Get public parameters of the key based on the provided X.509 certificate.
    """

    return cert.public_key().public_numbers()


def cert_get_public_key_der(cert: Certificate) -> bytes:
    """
    Get public key corresponding to the provided X.509 certificate and return it in DER format.
    """

    return cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def cert_load_file(file_name: str) -> Certificate:
    print('[#] Loading X.509 Certificate file: ' + os.path.basename(file_name))

    with open(file_name, 'rb') as f:
        data = f.read()

    cert = x509.load_pem_x509_certificate(data)
    cert_der = cert.public_bytes(Encoding.DER)

    cert_sha256 = hashlib.sha256(cert_der).hexdigest()

    print('-> X.509 Certificate SHA-256 (of DER encoded data)')
    print(cert_sha256)

    print()
    return cert
