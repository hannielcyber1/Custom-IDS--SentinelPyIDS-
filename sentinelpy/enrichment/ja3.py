"""
SentinelPy IDS - JA3 TLS Client Fingerprinting
Extracts and hashes TLS ClientHello parameters into JA3 MD5 fingerprints.
"""

import hashlib
from typing import Optional, List

# RFC 8701 GREASE values to ignore during JA3 calculation
GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
}

def is_grease(val: int) -> bool:
    """Returns True if the value matches an RFC 8701 GREASE reservation."""
    return val in GREASE_VALUES

def compute_ja3(payload_bytes: bytes) -> Optional[str]:
    """
    Parses a TLS ClientHello packet from raw payload bytes and computes its JA3 MD5 hash.
    Format: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    Returns None if the payload is not a valid TLS ClientHello.
    """
    if not payload_bytes or len(payload_bytes) < 44:
        return None

    try:
        # TLS Record Header: Byte 0 must be 0x16 (Handshake)
        # Byte 5 must be 0x01 (ClientHello)
        if payload_bytes[0] != 0x16 or payload_bytes[5] != 0x01:
            return None

        # Handshake TLS Version at offset 9-10
        tls_version = int.from_bytes(payload_bytes[9:11], "big")

        # Skip Client Random: 32 bytes starting at offset 11
        offset = 43
        if offset >= len(payload_bytes):
            return None

        session_id_len = payload_bytes[offset]
        offset += 1 + session_id_len
        if offset + 2 > len(payload_bytes):
            return None

        # Cipher Suites
        cipher_len = int.from_bytes(payload_bytes[offset:offset+2], "big")
        offset += 2
        if offset + cipher_len > len(payload_bytes):
            return None

        ciphers: List[str] = []
        for i in range(offset, offset + cipher_len, 2):
            if i + 2 <= len(payload_bytes):
                cipher_val = int.from_bytes(payload_bytes[i:i+2], "big")
                if not is_grease(cipher_val):
                    ciphers.append(str(cipher_val))

        offset += cipher_len
        if offset + 1 > len(payload_bytes):
            return None

        # Compression Methods
        comp_len = payload_bytes[offset]
        offset += 1 + comp_len

        # Extensions
        extensions: List[str] = []
        elliptic_curves: List[str] = []
        ec_point_formats: List[str] = []

        if offset + 2 <= len(payload_bytes):
            ext_len = int.from_bytes(payload_bytes[offset:offset+2], "big")
            offset += 2
            end_ext = min(len(payload_bytes), offset + ext_len)

            while offset + 4 <= end_ext:
                ext_type = int.from_bytes(payload_bytes[offset:offset+2], "big")
                ext_data_len = int.from_bytes(payload_bytes[offset+2:offset+4], "big")
                offset += 4
                ext_data = payload_bytes[offset:offset+ext_data_len]

                if not is_grease(ext_type):
                    extensions.append(str(ext_type))

                # Supported Groups / Elliptic Curves (0x000a = 10)
                if ext_type == 0x000a and len(ext_data) >= 2:
                    grp_len = int.from_bytes(ext_data[0:2], "big")
                    for gi in range(2, min(len(ext_data), 2 + grp_len), 2):
                        curve_val = int.from_bytes(ext_data[gi:gi+2], "big")
                        if not is_grease(curve_val):
                            elliptic_curves.append(str(curve_val))

                # EC Point Formats (0x000b = 11)
                elif ext_type == 0x000b and len(ext_data) >= 1:
                    pf_len = ext_data[0]
                    for pi in range(1, min(len(ext_data), 1 + pf_len)):
                        ec_point_formats.append(str(ext_data[pi]))

                offset += ext_data_len

        ciphers_str = "-".join(ciphers)
        extensions_str = "-".join(extensions)
        curves_str = "-".join(elliptic_curves)
        points_str = "-".join(ec_point_formats)

        ja3_string = f"{tls_version},{ciphers_str},{extensions_str},{curves_str},{points_str}"
        return hashlib.md5(ja3_string.encode("utf-8")).hexdigest()

    except Exception:
        return None
