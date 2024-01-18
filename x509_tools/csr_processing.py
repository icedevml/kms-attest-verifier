import hashlib
import os

from cryptography import x509
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.x509 import CertificateSigningRequest


def csr_get_key_public_numbers(csr: CertificateSigningRequest) -> RSAPublicNumbers:
    """
    Get public parameters of the key based on the provided CSR.
    """

    return csr.public_key().public_numbers()


def csr_get_public_key_der(csr: CertificateSigningRequest) -> bytes:
    """
    Get public key corresponding to the provided CSR and return it in DER format.
    """

    return csr.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def csr_load_file(file_name: str) -> CertificateSigningRequest:
    print('[#] Loading CSR file: ' + os.path.basename(file_name))

    with open(file_name, 'rb') as f:
        data = f.read()

    csr = x509.load_pem_x509_csr(data)
    csr_der = csr.public_bytes(Encoding.DER)

    csr_sha256 = hashlib.sha256(csr_der).hexdigest()

    print('-> CSR SHA-256 (of DER encoded data)')
    print(csr_sha256)

    print()
    return csr
