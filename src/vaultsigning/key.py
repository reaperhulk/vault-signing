import base64
import re
import typing

from oci.regions import REALMS, REGION_REALMS
from oci.key_management.models.sign_data_details import SignDataDetails
from oci.key_management.kms_crypto_client import KmsCryptoClient

from cryptography.hazmat.primitives import _serialization, hashes
from cryptography.hazmat.primitives._asymmetric import AsymmetricPadding
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    utils as asym_utils,
)
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15


class OCIRSAPrivateKey(rsa.RSAPrivateKey):
    def __init__(self, config, key_id, key_version_id):
        self._key_id = key_id
        self._key_version_id = key_version_id
        split_list = re.split(
            "ocid1\\.key\\.([\\w-]+)\\.([\\w-]+)\\.([\\w-]+)\\.([\\w]){60}",
            key_id
        )
        vault_ext = split_list[3]
        region = config.get("region")
        realm_name = REGION_REALMS.get(region)
        second_level_domain = REALMS.get(realm_name)
        crypto_endpoint = (
            "https://" + vault_ext + "-crypto.kms." + region +
            "." + second_level_domain
        )
        self._kms_crypto_client = KmsCryptoClient(config, crypto_endpoint)

    def _key_info(self):
        # Get key info from OCI Vault
        pass

    def sign(
        self,
        data: bytes,
        padding: AsymmetricPadding,
        algorithm: typing.Union[asym_utils.Prehashed, hashes.HashAlgorithm],
    ) -> bytes:
        assert not isinstance(algorithm, asym_utils.Prehashed)
        assert isinstance(padding, PKCS1v15)
        if isinstance(algorithm, hashes.SHA256):
            alg = SignDataDetails.SIGNING_ALGORITHM_SHA_256_RSA_PKCS1_V1_5
        elif isinstance(algorithm, hashes.SHA384):
            alg = SignDataDetails.SIGNING_ALGORITHM_SHA_384_RSA_PKCS1_V1_5
        elif isinstance(algorithm, hashes.SHA512):
            alg = SignDataDetails.SIGNING_ALGORITHM_SHA_512_RSA_PKCS1_V1_5

        h = hashes.Hash(algorithm)
        h.update(data)
        digest = base64.b64encode(h.finalize()).decode("utf8")

        sign_data_details = SignDataDetails(
            message=digest,
            key_id=self._key_id,
            key_version_id=self._key_version_id,
            signing_algorithm=alg,
            message_type=SignDataDetails.MESSAGE_TYPE_DIGEST,
        )
        response = self._kms_crypto_client.sign(sign_data_details)
        # TODO: handle errors.
        return base64.b64decode(response.data.signature)

    # Every method below here is unimplemented for now but needs to be
    # present to satisfy the interface.
    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        raise NotImplementedError()

    def key_size(self) -> int:
        raise NotImplementedError()

    def public_key(self) -> "rsa.RSAPublicKey":
        raise NotImplementedError()

    def private_numbers(self) -> "rsa.RSAPrivateNumbers":
        raise NotImplementedError()

    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError()
