"""
Client certificate handling: PKCS#12 (.p12/.pfx) -> temporary PEM, and
login/password auto-enrollment (the standard GoATAK/TAK Server flow: the
client generates its own key+CSR, the server only signs it).

Logic ported and adapted from agent_core.py (vision-agent) - it's already
proven in production against a real GoATAK there. It isn't video-agent
specific here; it's exactly the low-level TLS/certificate code that was
planned to be shared between the two projects.
"""

from __future__ import annotations

import base64
import os
import re
import tempfile
from typing import Optional

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

_CERT_BLOCK_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


class EnrollmentError(Exception):
    pass


def is_p12(path: Optional[str]) -> bool:
    return bool(path) and path.lower().endswith((".p12", ".pfx"))


def p12_to_temp_pem_cert_key(p12_path: str, password: Optional[str]) -> tuple[str, str]:
    """client.p12 -> temporary (cert.pem, key.pem). The caller must delete
    both files right after ssl.SSLContext.load_cert_chain()."""
    with open(p12_path, "rb") as f:
        data = f.read()
    key, cert, extra_certs = pkcs12.load_key_and_certificates(
        data, password.encode() if password else None,
    )
    if key is None or cert is None:
        raise ValueError(
            f"{p12_path}: no private key or certificate found in the PKCS#12 "
            f"(wrong password, or the file doesn't contain a client key+cert pair)"
        )

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    for c in (extra_certs or []):
        cert_pem += c.public_bytes(serialization.Encoding.PEM)

    key_fd = tempfile.NamedTemporaryFile(suffix=".key", delete=False)
    key_fd.write(key_pem)
    key_fd.close()
    os.chmod(key_fd.name, 0o600)

    cert_fd = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    cert_fd.write(cert_pem)
    cert_fd.close()
    os.chmod(cert_fd.name, 0o600)

    return cert_fd.name, key_fd.name


def p12_truststore_to_temp_pem(p12_path: str, password: Optional[str]) -> str:
    """truststore.p12 (usually built via keytool) -> temporary PEM with the
    CA chain. In keytool-built containers the certificate often ends up in
    extra_certs rather than the main slot - we pull from both places."""
    with open(p12_path, "rb") as f:
        data = f.read()
    key, cert, extra_certs = pkcs12.load_key_and_certificates(
        data, password.encode() if password else None,
    )
    certs = ([cert] if cert else []) + list(extra_certs or [])
    if not certs:
        raise ValueError(f"{p12_path}: no certificate found in the PKCS#12 "
                          f"(wrong password, or an empty truststore)")
    pem = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)
    fd = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    fd.write(pem)
    fd.close()
    os.chmod(fd.name, 0o600)
    return fd.name


def _cert_str_to_pem(cert_str: str) -> bytes:
    cert_str = cert_str.strip()
    if "BEGIN CERTIFICATE" in cert_str:
        return cert_str.encode()
    der = base64.b64decode(cert_str)
    cert = x509.load_der_x509_certificate(der)
    return cert.public_bytes(serialization.Encoding.PEM)


def enroll_certificate(
    host: str,
    enroll_port: int,
    username: str,
    password: str,
    client_uid: str,
    out_cert_path: str,
    out_key_path: str,
    out_ca_path: Optional[str] = None,
) -> None:
    """
    Auto-enroll: the user enters a domain + login/password, the relay
    generates its own key+CSR and gets back a signed certificate (+ CA
    chain) from the standard GoATAK/TAK Server enrollment endpoint. The
    result is written to PEM files at the given paths - the server is then
    added to config.yaml like any other PEM-based server.
    """
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)])
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    csr_body = (
        csr_pem.replace("-----BEGIN CERTIFICATE REQUEST-----\n", "")
        .replace("-----END CERTIFICATE REQUEST-----\n", "")
        .replace("-----END CERTIFICATE REQUEST-----", "")
    )

    url = f"https://{host}:{enroll_port}/Marti/api/tls/signClient/v2"
    try:
        resp = requests.post(
            url, params={"clientUID": client_uid, "version": "2"},
            data=csr_body, headers={"Content-Type": "application/x-www-form-urlencoded"},
            auth=(username, password), verify=False, timeout=20,
        )
    except requests.RequestException as exc:
        raise EnrollmentError(f"could not reach {url}: {exc}") from exc

    if resp.status_code != 200:
        raise EnrollmentError(f"server returned {resp.status_code}: {resp.text[:500]}")

    try:
        certs = resp.json()
    except ValueError as exc:
        raise EnrollmentError(f"response was not JSON: {resp.text[:500]}") from exc

    if "signedCert" not in certs:
        raise EnrollmentError(f"response has no signedCert: {certs}")

    with open(out_key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(out_cert_path, "wb") as f:
        f.write(_cert_str_to_pem(certs["signedCert"]))

    if out_ca_path:
        ca_certs = [v for k, v in certs.items() if k.lower().startswith("ca")]
        if ca_certs:
            with open(out_ca_path, "wb") as f:
                for c in ca_certs:
                    f.write(_cert_str_to_pem(c))
                    f.write(b"\n")


def get_cert_identity(cert_path: str, password: Optional[str] = None) -> Optional[str]:
    """
    Reads the Common Name (CN) out of the client certificate itself -
    this IS the identity the TAK server sees this connection as (matches
    what shows up under the server's own "Devices"/logins list). Works
    regardless of how the cert was obtained (enroll, uploaded p12, plain
    PEM) - unlike the enroll username, which is only known if the relay
    itself did the enrolling.

    Returns None on any failure (missing file, wrong password, no cert in
    the container, etc.) - this is a display nicety, never allowed to
    break the caller.
    """
    try:
        if is_p12(cert_path):
            with open(cert_path, "rb") as f:
                data = f.read()
            _key, cert, _extra = pkcs12.load_key_and_certificates(
                data, password.encode() if password else None,
            )
            if cert is None:
                return None
        else:
            with open(cert_path, "rb") as f:
                data = f.read()
            match = _CERT_BLOCK_RE.search(data)
            if not match:
                return None
            cert = x509.load_pem_x509_certificate(match.group(0))

        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            return str(cn_attrs[0].value)
        return cert.subject.rfc4514_string()
    except Exception:
        return None
