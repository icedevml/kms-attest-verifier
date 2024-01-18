from cryptography import x509
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.x509 import CertificateSigningRequest


def csr_get_key_public_numbers(csr: CertificateSigningRequest) -> RSAPublicNumbers:
    """
    Get public parameters of the key based on the provided CSR.
    """

    return csr.public_key().public_numbers()


def csr_get_public_key_pem(csr: CertificateSigningRequest) -> str:
    """
    Get public key corresponding to the provided CSR and return it in PEM format.
    """

    return csr.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode('ascii')


def csr_load_file(file_name: str) -> CertificateSigningRequest:
    with open(file_name, 'rb') as f:
        return x509.load_pem_x509_csr(f.read())
