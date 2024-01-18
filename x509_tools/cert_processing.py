from cryptography import x509
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.x509 import Certificate


def cert_get_key_public_numbers(cert: Certificate) -> RSAPublicNumbers:
    """
    Get public parameters of the key based on the provided X.509 certificate.
    """

    return cert.public_key().public_numbers()


def cert_get_public_key_pem(cert: Certificate) -> str:
    """
    Get public key corresponding to the provided X.509 certificate and return it in PEM format.
    """

    return cert.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode('ascii')


def cert_load_file(file_name: str) -> Certificate:
    with open(file_name, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read())
