import argparse

from kms_certs.verify_attestation_chains import verify as verify_google_attest
from marvell_hsm.hsm_checks import hsm_check_priv_key_attrs, hsm_get_key_public_numbers, hsm_get_public_key_pem
from marvell_hsm.hsm_v2_parse import get_priv_key_attrs
from x509_tools.cert_processing import cert_load_file, cert_get_key_public_numbers, cert_get_public_key_pem
from x509_tools.csr_processing import csr_load_file, csr_get_public_key_pem, csr_get_key_public_numbers


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--attestation-file', help='The name of attestation file.', required=True)
    parser.add_argument('--attestation-chain', help='The name of attestation certificate chain file.')
    parser.add_argument('--ec-curve', help='Name of the elliptic curve in case when the key in question is an EC key.')
    parser.add_argument('--csr-file', help='The name of CSR file.')
    parser.add_argument('--cert-file', help='The name of the X.509 certificate file.')
    args = parser.parse_args()

    hsm_privkey_attrs = get_priv_key_attrs(args.attestation_file)
    hsm_check_priv_key_attrs(hsm_privkey_attrs)
    hsm_pub_numbers = hsm_get_key_public_numbers(hsm_privkey_attrs, args.ec_curve)

    print('[#] Public key from the attestation file')
    print(hsm_get_public_key_pem(hsm_pub_numbers).strip())
    print()

    if args.csr_file:
        print('[#] Verify public key in CSR file')
        csr = csr_load_file(args.csr_file)
        csr_pub_numbers = csr_get_key_public_numbers(csr)

        if hsm_pub_numbers != csr_pub_numbers:
            raise RuntimeError('Key in the CSR doesn\'t match the attestation file.')

        enc = csr_get_public_key_pem(csr)
        print('OK - Public key is matching between the provided CSR and the attestation file.')
        print(enc)
        print()

    if args.cert_file:
        print('[#] Verify public key in X.509 certificate file')
        cert = cert_load_file(args.cert_file)
        cert_pub_numbers = cert_get_key_public_numbers(cert)

        if hsm_pub_numbers != cert_pub_numbers:
            raise RuntimeError('Key in the X.509 certificate doesn\'t match the attestation file.')

        enc = cert_get_public_key_pem(cert)
        print('OK - Public key is matching between the provided X.509 certificate and the attestation file.')
        print(enc)
        print()

    if args.attestation_chain:
        print('[#] Verify attestation chain of certificates.')
        res = verify_google_attest(args.attestation_chain, args.attestation_file)
        print()

        if not res:
            raise RuntimeError('Failed to verify certificates of the HSM attest.')

    print('[#] VERIFIED SUCCESFULLY')


if __name__ == '__main__':
    main()
