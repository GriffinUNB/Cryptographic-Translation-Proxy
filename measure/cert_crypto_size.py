#!/usr/bin/env python3
"""Measure the classical and PQC crypto byte sizes of an X.509 certificate.

Uses standard tools (openssl + cryptography) and a documented, DETERMINISTIC
signature size per algorithm (ECDSA DER signatures are variable-length by 1-2 B
because r/s may need a leading 0x00 octet, so we use the standard DER size).

Definitions:
  classical_crypto = EC SubjectPublicKeyInfo DER length + ECDSA signature size
  pqc_crypto       = ML-DSA SPKI DER length + ML-DSA signature size

Hybrid (Catalyst) certificates carry the secondary (PQC) key/signature in the
draft-lamps hybrid-cert extensions:
  2.5.29.72  subjectAltPublicKeyInfo        (alternative public key)
  2.5.29.73  alternativeSignatureAlgorithm
  2.5.29.74  alternativeSignatureValue      (alternative signature)

Usage:
    python3 cert_crypto_size.py <cert.pem...>        # prints "<classical> <pqc>"
"""
import subprocess
import sys

from cryptography import x509

OID_ALT_SPKI = "2.5.29.72"
OID_ALT_SIGALG = "2.5.29.73"

SIG_SIZE = {
    "secp256r1": 72, "secp384r1": 104, "secp521r1": 139,          # ECDSA
    "2.16.840.1.101.3.4.3.17": 2420,   # ML-DSA-44
    "2.16.840.1.101.3.4.3.18": 3309,   # ML-DSA-65
    "2.16.840.1.101.3.4.3.19": 4627,   # ML-DSA-87
}


def _der_len_of_pubkey(pem_path):
    """SubjectPublicKeyInfo DER length for the certificate's primary public key."""
    spki_pem = subprocess.run(
        ["openssl", "x509", "-in", pem_path, "-pubkey", "-noout"],
        capture_output=True, text=True).stdout.encode()
    der = subprocess.run(
        ["openssl", "pkey", "-pubin", "-inform", "PEM", "-outform", "DER"],
        input=spki_pem, capture_output=True).stdout
    return len(der)


def _oid_from_algid(der):
    """Dotted OID from a DER AlgorithmIdentifier (SEQUENCE { OBJECT IDENTIFIER, ... })."""
    if not der or der[0] != 0x30:
        return ""
    off = 2
    # skip SEQUENCE length octets
    first = der[1]
    if first >= 0x80:
        off = 2 + (first & 0x7F)
    if off >= len(der) or der[off] != 0x06:
        return ""
    oid_bytes = der[off + 2:off + 2 + der[off + 1]]
    out = [oid_bytes[0] // 40, oid_bytes[0] % 40]
    val = 0
    for b in oid_bytes[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            out.append(val); val = 0
    return ".".join(map(str, out))


def _primary_sig_key(cert):
    """Key into SIG_SIZE for the primary signature: curve name (EC) or ML-DSA OID."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        key = cert.public_key()
        if isinstance(key, ec.EllipticCurvePublicKey):
            return key.curve.name
    except Exception:
        pass
    return cert.signature_algorithm_oid.dotted_string


def _alt_sig_key(cert):
    """Key into SIG_SIZE for the alternative (secondary) signature algorithm."""
    for ext in cert.extensions:
        if ext.oid.dotted_string == OID_ALT_SIGALG:
            return _oid_from_algid(ext.value.value)
    return ""


def cert_crypto(pem_path):
    cert = x509.load_pem_x509_certificate(open(pem_path, "rb").read())

    primary_oid = cert.signature_algorithm_oid.dotted_string
    primary_ec = primary_oid.startswith("1.2.840.10045")          # ECDSA
    primary_pq = primary_oid.startswith("2.16.840.1.101.3.4.3")   # ML-DSA

    primary_spki = _der_len_of_pubkey(pem_path)
    primary_sig = SIG_SIZE.get(_primary_sig_key(cert), 0)

    alt_spki = alt_sig = 0
    for ext in cert.extensions:
        oid = ext.oid.dotted_string
        if oid == OID_ALT_SPKI:
            alt_spki = len(ext.value.value)
    alt_sig = SIG_SIZE.get(_alt_sig_key(cert), 0) if alt_spki else 0

    if primary_ec:
        classical = primary_spki + primary_sig
        pqc = alt_spki + alt_sig                      # Catalyst alternative = PQC side
    elif primary_pq:
        classical = 0
        pqc = primary_spki + primary_sig
    else:
        classical = primary_spki + primary_sig
        pqc = alt_spki + alt_sig
    return classical, pqc


def main():
    for p in sys.argv[1:]:
        c, q = cert_crypto(p)
        print(f"{c} {q}")


if __name__ == "__main__":
    main()
