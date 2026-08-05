from __future__ import annotations

import base64
import copy
import tempfile
from pathlib import Path
from typing import Any

from .util import AuthorityError, canonical_json_bytes, read_json, run, sha256_file, write_json


_SIGNATURE_ALGORITHM = "RSASSA-PKCS1-v1_5-SHA256"


def unsigned_attestation(attestation: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(attestation)
    value.pop("signature", None)
    return value


def sign_attestation(attestation: dict[str, Any], private_key_path: str, *, key_id: str) -> dict[str, Any]:
    payload = canonical_json_bytes(unsigned_attestation(attestation))
    with tempfile.TemporaryDirectory() as directory:
        payload_path = Path(directory, "payload.json")
        signature_path = Path(directory, "signature.bin")
        payload_path.write_bytes(payload)
        run([
            "openssl",
            "dgst",
            "-sha256",
            "-sign",
            private_key_path,
            "-out",
            str(signature_path),
            str(payload_path),
        ])
        signature = base64.b64encode(signature_path.read_bytes()).decode("ascii")
    signed = copy.deepcopy(attestation)
    signed["signature"] = {
        "algorithm": _SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "value_base64": signature,
    }
    return signed


def verify_attestation(attestation: dict[str, Any], public_key_path: str, *, expected_key_id: str | None = None) -> None:
    signature = attestation.get("signature")
    if not isinstance(signature, dict):
        raise AuthorityError("ATTESTATION_SIGNATURE_MISSING")
    if signature.get("algorithm") != _SIGNATURE_ALGORITHM:
        raise AuthorityError("ATTESTATION_SIGNATURE_ALGORITHM_UNSUPPORTED")
    if expected_key_id is not None and signature.get("key_id") != expected_key_id:
        raise AuthorityError("ATTESTATION_SIGNING_KEY_MISMATCH")
    try:
        signature_bytes = base64.b64decode(signature["value_base64"], validate=True)
    except Exception as error:
        raise AuthorityError("ATTESTATION_SIGNATURE_ENCODING_INVALID") from error
    with tempfile.TemporaryDirectory() as directory:
        payload_path = Path(directory, "payload.json")
        signature_path = Path(directory, "signature.bin")
        payload_path.write_bytes(canonical_json_bytes(unsigned_attestation(attestation)))
        signature_path.write_bytes(signature_bytes)
        result = run([
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            public_key_path,
            "-signature",
            str(signature_path),
            str(payload_path),
        ], check=False)
        if result.returncode != 0:
            raise AuthorityError("ATTESTATION_SIGNATURE_INVALID")


def public_key_fingerprint(public_key_path: str) -> str:
    with tempfile.TemporaryDirectory() as directory:
        der_path = Path(directory, "key.der")
        run(["openssl", "pkey", "-pubin", "-in", public_key_path, "-outform", "DER", "-out", str(der_path)])
        return sha256_file(der_path)
