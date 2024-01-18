# Audit attestation files from GCP KMS

This tool allows to verify the HSM attestation files provided by Google Cloud KMS. It performs the following checks:

* Whether the key parameters in the attestation file are correct (key was locally generated on HSM, key is not exportable etc);
* Whether the attestation file is correctly signed by the HSM manufacturer and Google;
* Whether the attestation file is related with the same private key as the one that was used to sign the provided CSR or X.509 Certificate;

## Purpose of this tool

The tool was developed in order to help internal auditors to verify compliance with CA/B Forum requirements whenever
it is mandatory for the certificate's private key to be securely generated on the HSM.

## Installation

1. Clone the repository.
2. Create and activate the virtualenv.
3. Run `pip3 install -r requirements.txt`

## Obtaining KMS attestations

The attestation bundles for the keys hosted in Google Cloud KMS can be downloaded by navigating into the key properties
in the Cloud Console, and choosing "Actions" -> "Verify attestation" -> "Download attestation bundle" under the target
key version to be audited.

## Usage

Check whether the attestation file is correctly signed by Google and HSM manufacturer, and whether the corresponding
key was initially generated on the HSM and is marked non-exportable:
```
python3 audit_hsm.py \
    --attestation-file MyRing-MyKey1-1-CAVIUM_V2_COMPRESSED-attestation.dat \
    --attestation-chain MyRing-MyKey1-1-combined-chain.pem
```

Perform the checks described above and additionally compare the public key in the attestation file with
the public key used to sign the particular CSR file (useful as an additional check before the CSR is submitted
to the CA):

```
python3 audit_hsm.py \
    --attestation-file MyRing-MyKey1-1-CAVIUM_V2_COMPRESSED-attestation.dat \
    --attestation-chain MyRing-MyKey1-1-combined-chain.pem
    --csr-file my_csr.pem
```

Perform the checks described above and additionally compare the public key in the attestation file with
the public key used to sign the particular X.509 Certificate file (useful to verify whether the certificate
was signed using a key that is securely hosted in HSM):
```
python3 audit_hsm.py \
    --attestation-file MyRing-MyKey1-1-CAVIUM_V2_COMPRESSED-attestation.dat \
    --attestation-chain MyRing-MyKey1-1-combined-chain.pem
    --cert-file my_cert.pem
```

## Note

This projects contains code portions that were authored by Google LLC and Marvell.
