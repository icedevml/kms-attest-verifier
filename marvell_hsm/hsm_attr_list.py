"""
List of attributes available in Marvell LiquidSecurity attestation files.
Source: https://www.marvell.com/products/security-solutions/nitrox-hs-adapters/software-key-attestation.html
"""

# Class type of the key.
OBJ_ATTR_CLASS = 0x0

# Identifies the key as a token key.
OBJ_ATTR_TOKEN = 0x1

# Indicates if this is a shared key or a private key (for symmetric or asymmetric keys).
OBJ_ATTR_PRIVATE = 0x2

# Key description.
OBJ_ATTR_LABEL = 0x3

# The key can be trusted for the application that it was created.
OBJ_ATTR_TRUSTED = 0x86

# Subclass type of the key.
OBJ_ATTR_KEY_TYPE = 0x100

# Key identifier.
OBJ_ATTR_ID = 0x102

# Always true for keys generated on HSM.
OBJ_ATTR_SENSITIVE = 0x103

# Indicates if key can be used to encrypt data for operations like RSA_Encrypt. Not applicable to EC keys.
OBJ_ATTR_ENCRYPT = 0x104

# Indicates if key can be used to decrypt data for operations like RSA_Decrypt. Not applicable to EC keys.
OBJ_ATTR_DECRYPT = 0x105

# Indicates if key can be used to wrap other keys.
OBJ_ATTR_WRAP = 0x106

# Indicates if key can be used to unwrap other keys.
OBJ_ATTR_UNWRAP = 0x107

# Indicates if key can be used for signing operations.
OBJ_ATTR_SIGN = 0x108

# Indicates if key can be used for verifying operations.
OBJ_ATTR_VERIFY = 0x10a

# Indicates if key supports key derivation (i.e. if other keys can be derived from this one).
OBJ_ATTR_DERIVE = 0x10c

# RSA key modulus value (or ECDSA public key in case of EC key)
OBJ_ATTR_MODULUS = 0x120

# RSA key size in bits.
OBJ_ATTR_MODULUS_BITS = 0x121

# RSA key public exponent value.
OBJ_ATTR_PUBLIC_EXPONENT = 0x122

# Length in bytes of any value.
OBJ_ATTR_VALUE_LEN = 0x161

# Indicates if key can be extracted.
OBJ_ATTR_EXTRACTABLE = 0x162

# Indicates if key was generated locally
OBJ_ATTR_LOCAL = 0x163

# Indicates if key can never be extracted.
OBJ_ATTR_NEVER_EXTRACTABLE = 0x164

# Indicates if key has always had the OBJ_ATTR_SENSITIVE attribute set.
OBJ_ATTR_ALWAYS_SENSITIVE = 0x165

# Key Check Value.
OBJ_ATTR_KCV = 0x173

# Extended Attribute #1
OBJ_EXT_ATTR1 = 0x1000

# Extended Key Check Value.
OBJ_ATTR_EKCV = 0x1003

# Indicates if key can only be wrapped with a wrapping key that has OBJ_ATTR_TRUSTED set.
OBJ_ATTR_WRAP_WITH_TRUSTED = 0x210

# Indicates if key can be split into multiple parts.
OBJ_ATTR_SPLITTABLE = 0x80000002

# Indicate if it is part of the key split.
OBJ_ATTR_IS_SPLIT = 0x80000003

# Indicate if key supports encryption.
OBJ_ATTR_ENCRYPT_KEY_MECHANISMS = 0x80000174

# Indicate if key supports decryption.
OBJ_ATTR_DECRYPT_KEY_MECHANISMS = 0x80000175

# Indicate if key supports signing.
OBJ_ATTR_SIGN_KEY_MECHANISMS = 0x80000176

# Indicate if key supports signature verification.
OBJ_ATTR_VERIFY_KEY_MECHANISMS = 0x80000177

# Indicate if key supports key wrapping.
OBJ_ATTR_WRAP_KEY_MECHANISMS = 0x80000178

# Indicate if key supports key unwrapping.
OBJ_ATTR_UNWAP_KEY_MECHANISMS = 0x80000179

# Indicate if key supports key derivation
OBJ_ATTR_DERIVE_KEY_MECHANISMS = 0x80000180

_KNOWN_KEYS = [
    "OBJ_ATTR_CLASS",
    "OBJ_ATTR_TOKEN",
    "OBJ_ATTR_PRIVATE",
    "OBJ_ATTR_LABEL",
    "OBJ_ATTR_TRUSTED",
    "OBJ_ATTR_KEY_TYPE",
    "OBJ_ATTR_ID",
    "OBJ_ATTR_SENSITIVE",
    "OBJ_ATTR_ENCRYPT",
    "OBJ_ATTR_DECRYPT",
    "OBJ_ATTR_WRAP",
    "OBJ_ATTR_UNWRAP",
    "OBJ_ATTR_SIGN",
    "OBJ_ATTR_VERIFY",
    "OBJ_ATTR_DERIVE",
    "OBJ_ATTR_MODULUS",
    "OBJ_ATTR_MODULUS_BITS",
    "OBJ_ATTR_PUBLIC_EXPONENT",
    "OBJ_ATTR_VALUE_LEN",
    "OBJ_ATTR_EXTRACTABLE",
    "OBJ_ATTR_LOCAL",
    "OBJ_ATTR_NEVER_EXTRACTABLE",
    "OBJ_ATTR_ALWAYS_SENSITIVE",
    "OBJ_ATTR_KCV",
    "OBJ_EXT_ATTR1",
    "OBJ_ATTR_EKCV",
    "OBJ_ATTR_WRAP_WITH_TRUSTED",
    "OBJ_ATTR_SPLITTABLE",
    "OBJ_ATTR_IS_SPLIT",
    "OBJ_ATTR_ENCRYPT_KEY_MECHANISMS",
    "OBJ_ATTR_DECRYPT_KEY_MECHANISMS",
    "OBJ_ATTR_SIGN_KEY_MECHANISMS",
    "OBJ_ATTR_VERIFY_KEY_MECHANISMS",
    "OBJ_ATTR_WRAP_KEY_MECHANISMS",
    "OBJ_ATTR_UNWAP_KEY_MECHANISMS",
    "OBJ_ATTR_DERIVE_KEY_MECHANISMS"
]
