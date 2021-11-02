A proof of concept of implementing the cryptography private key interface with a cloud KMS (in this case OCI Vault) and then using it to sign a certificate using the cryptography X.509 APIs.

You need an OCI config, a vault key\_id, and its key\_version\_id to run this example. See vaultsigner.py for the very simple implementation.

You'll also need to install the package, then force upgrade cryptography despite pip's protestations. This is because the OCI SDK version caps cryptography at a version lower than required.

```python
import datetime

from oci.config import from_file

from vaultsigning.key import OCIRSAPrivateKey
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

config = from_file("config")

not_valid_before = datetime.datetime.now()
not_valid_after = not_valid_before + datetime.timedelta(days=90)

key_id = 'key_ocid_goes_here'
key_version_id = 'version_id_goes_here'
issuer_private_key = OCIRSAPrivateKey(config, key_id, key_version_id)
subject_private_key = rsa.generate_private_key(65537, 2048)

name = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(
            NameOID.STATE_OR_PROVINCE_NAME, "Texas"
        ),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Austin"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PyCA"),
        x509.NameAttribute(
            NameOID.COMMON_NAME, "cryptography.io"
        ),
    ]
)

builder = (
    x509.CertificateBuilder()
    .serial_number(x509.random_serial_number())
    .issuer_name(name)
    .subject_name(name)
    .public_key(subject_private_key.public_key())
    .add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        True,
    )
    .add_extension(
        x509.SubjectAlternativeName([x509.DNSName("cryptography.io")]),
        critical=False,
    )
    .not_valid_before(not_valid_before)
    .not_valid_after(not_valid_after)
)

cert = builder.sign(issuer_private_key, hashes.SHA256())

print(cert.public_bytes(serialization.Encoding.PEM))
print(
    subject_private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
)
```
