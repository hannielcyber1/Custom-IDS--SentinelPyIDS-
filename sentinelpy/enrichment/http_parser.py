"""
SentinelPy IDS - Lightweight HTTP Protocol Parser
Extracts HTTP request/response headers, methods, URIs, and user-agents from TCP streams.
"""

from typing import Optional, Dict, Any

KNOWN_METHODS = {
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"
}

def parse_http(payload_bytes: bytes) -> Optional[Dict[str, Any]]:
    """
    Parses raw TCP payload into an HTTP metadata dictionary.
    Returns None if payload is not an HTTP request or response.
    """
    if not payload_bytes or len(payload_bytes) < 4:
        return None

    try:
        # Check if the payload starts with an HTTP response or method
        # Find header boundary (\r\n\r\n or \n\n)
        header_end = payload_bytes.find(b"\r\n\r\n")
        if header_end != -1:
            header_bytes = payload_bytes[:header_end]
        else:
            header_end = payload_bytes.find(b"\n\n")
            if header_end != -1:
                header_bytes = payload_bytes[:header_end]
            else:
                # If incomplete or single packet, inspect the first 4KB
                header_bytes = payload_bytes[:4096]

        header_text = header_bytes.decode("utf-8", errors="ignore")
        lines = header_text.splitlines()
        if not lines:
            return None

        start_line = lines[0].strip()
        if not start_line:
            return None

        is_response = start_line.startswith("HTTP/")
        method: Optional[str] = None
        uri: Optional[str] = None
        http_version: Optional[str] = None
        status_code: Optional[int] = None
        reason: Optional[str] = None

        if is_response:
            parts = start_line.split(" ", 2)
            http_version = parts[0]
            if len(parts) > 1:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    status_code = None
            if len(parts) > 2:
                reason = parts[2]
        else:
            parts = start_line.split(" ")
            if len(parts) < 2 or parts[0].upper() not in KNOWN_METHODS:
                return None
            method = parts[0].upper()
            uri = parts[1]
            if len(parts) > 2:
                http_version = parts[2]
            else:
                http_version = "HTTP/1.1"

        # Parse headers (up to 10 headers stored)
        headers: Dict[str, str] = {}
        host: Optional[str] = None
        user_agent: Optional[str] = None
        content_type: Optional[str] = None

        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            h_key = key.strip()
            h_val = val.strip()

            k_lower = h_key.lower()
            if k_lower == "host" and host is None:
                host = h_val
            elif k_lower == "user-agent" and user_agent is None:
                user_agent = h_val
            elif k_lower == "content-type" and content_type is None:
                content_type = h_val

            if len(headers) < 10:
                headers[h_key] = h_val

        return {
            "method": method,
            "uri": uri,
            "http_version": http_version,
            "status_code": status_code,
            "reason": reason,
            "host": host,
            "user_agent": user_agent,
            "content_type": content_type,
            "headers": headers,
        }

    except Exception:
        return None
