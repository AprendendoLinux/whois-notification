"""Inspeção do certificado TLS (mesmo inválido ou expirado)."""
import socket
import ssl
from datetime import timezone

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID


def _name_attr(name: x509.Name, oid) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else None


def _fetch_cert(host: str, timeout: float) -> tuple[bytes, str | None, str | None]:
    """Retorna (certificado DER, versão TLS, erro de validação)."""
    # 1) Tentativa validada: descobre se a cadeia é confiável
    verify_error = None
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return tls.getpeercert(binary_form=True), tls.version(), None
    except ssl.SSLCertVerificationError as e:
        verify_error = e.verify_message or str(e)
    # 2) Sem validação: obtém o certificado para inspeção
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, 443), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True), tls.version(), verify_error


def lookup(domain: str, timeout: float = 8.0) -> dict:
    last_exc = None
    for host in (domain, f"www.{domain}"):
        try:
            der, tls_version, verify_error = _fetch_cert(host, timeout)
            break
        except (OSError, ssl.SSLError) as e:
            last_exc = e
    else:
        raise ConnectionError(f"Não foi possível conectar na porta 443: {last_exc}")

    cert = x509.load_der_x509_certificate(der)
    try:
        sans = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    not_after = cert.not_valid_after_utc.astimezone(timezone.utc)
    not_before = cert.not_valid_before_utc.astimezone(timezone.utc)
    issuer_org = _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME)
    issuer_cn = _name_attr(cert.issuer, NameOID.COMMON_NAME)

    return {
        "host": host,
        "subject": _name_attr(cert.subject, NameOID.COMMON_NAME),
        "issuer": issuer_org or issuer_cn,
        "issuer_cn": issuer_cn,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "sans": sorted(sans)[:100],
        "san_count": len(sans),
        "serial": format(cert.serial_number, "X"),
        "signature_algorithm": getattr(cert.signature_hash_algorithm, "name", None),
        "key_type": type(cert.public_key()).__name__.replace("_", "").replace("PublicKey", ""),
        "key_size": getattr(cert.public_key(), "key_size", None),
        "tls_version": tls_version,
        "valid": verify_error is None,
        "verify_error": verify_error,
        "lifetime_days": (not_after - not_before).days,
    }
