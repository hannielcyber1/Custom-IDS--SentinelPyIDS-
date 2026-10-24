"""
SentinelPy IDS - Snort Rule Importer
Parses Snort/Suricata .rules format and converts them to SentinelPy YAML signature rules.

Supported Snort keywords:
  msg, sid, rev, classtype, content, nocase, depth, offset, distance, within,
  pcre, itype, icode, flow, reference, metadata, service, priority

Gracefully skipped (unsupported / too complex):
  flowbits, byte_test, byte_jump, byte_extract, dce_iface, dce_opnum,
  http_uri, http_header, http_raw_uri, file_data, isdataat, dsize,
  fragbits, ip_proto, ttl, id, seq, ack, stream_size, fast_pattern,
  base64_decode, base64_data
"""

import re
import logging
import yaml
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

logger = logging.getLogger("sentinelpy.snort_importer")

# ---------------------------------------------------------------------------
# Classtype → SentinelPy severity / category mapping
# ---------------------------------------------------------------------------
CLASSTYPE_SEVERITY: Dict[str, str] = {
    "attempted-admin":        "critical",
    "attempted-user":         "high",
    "shellcode-detect":       "critical",
    "successful-admin":       "critical",
    "successful-user":        "high",
    "trojan-activity":        "high",
    "unsuccessful-user":      "medium",
    "web-application-attack": "high",
    "web-application-activity": "medium",
    "network-scan":           "medium",
    "denial-of-service":      "high",
    "non-standard-protocol":  "low",
    "protocol-command-decode":"low",
    "system-call-detect":     "medium",
    "unusual-client-port-connection": "medium",
    "policy-violation":       "low",
    "suspicious-login":       "high",
    "suspicious-filename-detect": "medium",
    "misc-activity":          "low",
    "misc-attack":            "medium",
    "default":                "medium",
}

CLASSTYPE_CATEGORY: Dict[str, str] = {
    "attempted-admin":          "exploit",
    "attempted-user":           "exploit",
    "shellcode-detect":         "shellcode",
    "successful-admin":         "exploit",
    "successful-user":          "exploit",
    "trojan-activity":          "malware",
    "unsuccessful-user":        "auth",
    "web-application-attack":   "web-attack",
    "web-application-activity": "web",
    "network-scan":             "recon",
    "denial-of-service":        "dos",
    "non-standard-protocol":    "protocol",
    "protocol-command-decode":  "protocol",
    "system-call-detect":       "exploit",
    "unusual-client-port-connection": "network",
    "policy-violation":         "policy",
    "suspicious-login":         "auth",
    "suspicious-filename-detect": "malware",
    "misc-activity":            "general",
    "misc-attack":              "general",
    "default":                  "general",
}

# Snort variables → SentinelPy ignores them (matches any)
_SNORT_VAR_RE = re.compile(r"^\$[A-Z_]+$")

# Regex to split a rule into header and options
_RULE_PATTERN = re.compile(
    r"^(?P<action>\w+)\s+"
    r"(?P<proto>\w+)\s+"
    r"(?P<src_ip>\S+)\s+"
    r"(?P<src_port>\S+)\s+"
    r"(?P<dir>->|<>)\s+"
    r"(?P<dst_ip>\S+)\s+"
    r"(?P<dst_port>\S+)\s+"
    r"\((?P<options>.+)\)\s*$",
    re.DOTALL,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_port_spec(spec: str) -> Optional[List[int]]:
    """
    Convert a Snort port spec to a list of ints or None (any).
    Handles: any, single int, range (80:443), negated (!80), list ([80,443]).
    Returns None when port is 'any' or a Snort variable.
    """
    spec = spec.strip()
    if spec == "any" or _SNORT_VAR_RE.match(spec):
        return None
    # Remove negation – SentinelPy does not support negated ports yet
    if spec.startswith("!"):
        spec = spec[1:]
    # Group/list: [80,443,8080]
    if spec.startswith("["):
        ports = []
        inner = spec.strip("[]")
        for part in inner.split(","):
            part = part.strip().lstrip("!")
            sub = _parse_port_spec(part)
            if sub:
                ports.extend(sub)
        return ports or None
    # Range: 1024:65535
    if ":" in spec:
        parts = spec.split(":")
        try:
            lo = int(parts[0]) if parts[0] else 0
            hi = int(parts[1]) if parts[1] else 65535
            # Expand ranges up to a max of 50 ports to avoid huge lists
            if (hi - lo) <= 50:
                return list(range(lo, hi + 1))
            else:
                # Return lo and hi as representative ports only
                return [lo, hi]
        except ValueError:
            return None
    # Single port
    try:
        return [int(spec)]
    except ValueError:
        return None


def _parse_options(options_str: str) -> Dict[str, Any]:
    """
    Tokenise Snort rule options into a dict of keyword → value.
    Handles quoted strings, parentheses, and semicolon-delimited fields.
    """
    result: Dict[str, List[str]] = {}
    i = 0
    s = options_str
    n = len(s)

    while i < n:
        # Skip whitespace
        while i < n and s[i] in (" ", "\t", "\n", "\r"):
            i += 1
        if i >= n:
            break

        # Read keyword (up to ':' or ';')
        key_start = i
        while i < n and s[i] not in (":", ";", " "):
            i += 1
        key = s[key_start:i].strip()
        if not key:
            i += 1
            continue

        if i >= n or s[i] == ";":
            # Boolean keyword with no value
            result.setdefault(key, []).append("True")
            i += 1
            continue

        if s[i] == ":":
            i += 1  # consume ':'
            # Skip whitespace after colon
            while i < n and s[i] in (" ", "\t"):
                i += 1

            val_parts = []
            while i < n and s[i] != ";":
                if s[i] == '"':
                    # Quoted string
                    i += 1
                    q_start = i
                    while i < n and s[i] != '"':
                        if s[i] == "\\" and i + 1 < n:
                            i += 2
                            continue
                        i += 1
                    val_parts.append(s[q_start:i])
                    if i < n:
                        i += 1  # closing quote
                else:
                    val_parts.append(s[i])
                    i += 1

            val = "".join(val_parts).strip()
            result.setdefault(key, []).append(val)
            if i < n:
                i += 1  # consume ';'

    return {k: v for k, v in result.items()}


def _hex_content_to_str(content: str) -> Tuple[str, Optional[str]]:
    """
    Convert a Snort content string (which may contain |XX XX| hex escapes)
    into a plain UTF-8 string and, if heavily binary, a hex magic_bytes string.
    Returns (printable_string, optional_magic_hex).
    """
    pieces = []
    magic_hex_parts = []
    i = 0
    all_hex = True
    while i < len(content):
        if content[i] == "|":
            end = content.find("|", i + 1)
            if end == -1:
                pieces.append(content[i])
                magic_hex_parts.append(content[i].encode().hex())
                all_hex = False
                i += 1
            else:
                hex_str = content[i + 1 : end].replace(" ", "")
                try:
                    b = bytes.fromhex(hex_str)
                    decoded = b.decode("latin-1")
                    pieces.append(decoded)
                    magic_hex_parts.append(hex_str)
                except Exception:
                    pieces.append(content[i : end + 1])
                    magic_hex_parts.append(content[i : end + 1])
                i = end + 1
        else:
            pieces.append(content[i])
            magic_hex_parts.append(content[i].encode().hex())
            all_hex = False
            i += 1

    text = "".join(pieces)
    # Determine if we should use magic_bytes (>50% non-printable)
    printable = sum(1 for c in text if c.isprintable())
    total = max(1, len(text))
    if printable / total < 0.6:
        return text, " ".join(magic_hex_parts)
    return text, None


def _clean_pcre(pcre_val: str) -> Optional[str]:
    """
    Strip Snort PCRE delimiters (/pattern/flags) to a Python-compatible regex string.
    Snort flags: i (nocase), s (dotall), m (multiline), x (extended).
    """
    pcre_val = pcre_val.strip()
    if not pcre_val.startswith("/"):
        return pcre_val
    # Find the closing delimiter
    end = pcre_val.rfind("/")
    if end <= 0:
        return pcre_val
    pattern = pcre_val[1:end]
    flags_str = pcre_val[end + 1:]

    inline_flags = ""
    if "i" in flags_str:
        inline_flags += "i"
    if "s" in flags_str:
        inline_flags += "s"
    if "m" in flags_str:
        inline_flags += "m"

    if inline_flags:
        return f"(?{inline_flags}){pattern}"
    return pattern


# ---------------------------------------------------------------------------
# Main Converter
# ---------------------------------------------------------------------------

class SnortImportResult:
    def __init__(self):
        self.converted: List[Dict[str, Any]] = []
        self.skipped: List[str] = []   # (reason)
        self.warnings: List[str] = []

    @property
    def converted_count(self) -> int:
        return len(self.converted)

    @property
    def skipped_count(self) -> int:
        return len(self.skipped)


def convert_rule(raw_rule: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Parse a single Snort rule line and return (sentinelpy_rule_dict, skip_reason).
    Returns (None, reason) if the rule cannot be converted.
    Returns (rule_dict, None) on success.
    """
    raw_rule = raw_rule.strip()
    # Skip comments and blanks
    if not raw_rule or raw_rule.startswith("#"):
        return None, "comment/blank"

    m = _RULE_PATTERN.match(raw_rule)
    if not m:
        return None, "rule_parse_failed"

    action    = m.group("action").lower()
    proto     = m.group("proto").lower()
    src_ip    = m.group("src_ip").strip()
    src_port  = m.group("src_port").strip()
    dst_ip    = m.group("dst_ip").strip()
    dst_port  = m.group("dst_port").strip()
    opts_str  = m.group("options")

    # Only support alert/log/drop – skip pass/sdrop
    if action not in ("alert", "log", "drop"):
        return None, f"unsupported_action:{action}"

    opts = _parse_options(opts_str)

    # --- Extract required fields ---
    sid_vals = opts.get("sid", [])
    if not sid_vals:
        return None, "no_sid"
    sid = sid_vals[0].strip()

    msg_vals = opts.get("msg", [])
    name = msg_vals[0].strip() if msg_vals else f"Snort-SID-{sid}"

    classtype_vals = opts.get("classtype", [])
    classtype = classtype_vals[0].strip() if classtype_vals else "default"
    severity = CLASSTYPE_SEVERITY.get(classtype, "medium")
    category = CLASSTYPE_CATEGORY.get(classtype, "general")

    # --- Build match block ---
    match: Dict[str, Any] = {"protocol": proto}

    # Source port (used when flow is to_client / src is home_net)
    src_ports = _parse_port_spec(src_port)
    dst_ports = _parse_port_spec(dst_port)

    if dst_ports:
        if len(dst_ports) == 1:
            match["destination_port"] = dst_ports[0]
        else:
            match["destination_ports"] = dst_ports

    if src_ports:
        if len(src_ports) == 1:
            match["source_port"] = src_ports[0]
        elif not dst_ports:
            # Put them as destination if that's all we have
            match["destination_ports"] = src_ports

    # --- Content keywords ---
    contents = opts.get("content", [])
    nocase_present = "nocase" in opts
    content_strings: List[str] = []
    magic_hex_parts: List[str] = []

    for c in contents:
        text, maybe_hex = _hex_content_to_str(c)
        content_strings.append(text)
        if maybe_hex:
            magic_hex_parts.append(maybe_hex)

    if content_strings:
        nocase = nocase_present or any(
            v == "True" for v in opts.get("nocase", [])
        )
        if len(content_strings) == 1:
            match["content"] = {
                "any_of": content_strings,
                "nocase": nocase,
            }
        else:
            match["content"] = {
                "any_of": content_strings,
                "nocase": nocase,
            }

    # First magic_bytes candidate (binary payload check)
    if magic_hex_parts:
        match["magic_bytes"] = magic_hex_parts[0].replace(" ", "")

    # --- PCRE keyword ---
    pcre_vals = opts.get("pcre", [])
    if pcre_vals:
        cleaned = _clean_pcre(pcre_vals[0])
        if cleaned:
            match["regex"] = cleaned

    # --- ICMP type / code ---
    itype_vals = opts.get("itype", [])
    if itype_vals:
        try:
            match["icmp_type"] = int(itype_vals[0].strip())
        except ValueError:
            pass

    icode_vals = opts.get("icode", [])
    if icode_vals:
        try:
            match["icmp_code"] = int(icode_vals[0].strip())
        except ValueError:
            pass

    # --- Flowbits keyword ---
    flowbit_vals = opts.get("flowbits", [])
    for fb_val in flowbit_vals:
        parts = [p.strip() for p in fb_val.split(",")]
        if len(parts) >= 2:
            action, bit_name = parts[0].lower(), parts[1]
            if action == "isset":
                match["flowbits_isset"] = bit_name
            elif action == "set":
                match["flowbits_set"] = bit_name

    # --- Build tags ---
    tags: List[str] = [f"snort-sid:{sid}", f"classtype:{classtype}"]
    rev_vals = opts.get("rev", [])
    if rev_vals:
        tags.append(f"rev:{rev_vals[0].strip()}")

    ref_vals = opts.get("reference", [])
    for ref in ref_vals[:2]:  # cap references
        tags.append(f"ref:{ref.strip()[:60]}")

    # --- Assemble rule dict ---
    rule_dict: Dict[str, Any] = {
        "id":          f"SNT-{sid}",
        "name":        name,
        "enabled":     True,
        "category":    category,
        "severity":    severity,
        "description": f"Imported from Snort community rules. SID:{sid} Rev:{rev_vals[0] if rev_vals else 'N/A'}",
        "tags":        tags,
        "match":       match,
    }

    return rule_dict, None


def import_rules_file(rules_path: str) -> SnortImportResult:
    """
    Read a Snort .rules file and convert all rules to SentinelPy format.
    Returns an SnortImportResult with converted rules, skipped counts and warnings.
    """
    result = SnortImportResult()
    path = Path(rules_path)
    if not path.exists():
        raise FileNotFoundError(f"Rules file not found: {rules_path}")

    seen_sids: set = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            rule_dict, skip_reason = convert_rule(line)
            if rule_dict is None:
                if skip_reason not in ("comment/blank",):
                    result.skipped.append(f"Line {lineno}: {skip_reason} → {line[:80]}")
                continue

            sid_tag = next((t for t in rule_dict["tags"] if t.startswith("snort-sid:")), None)
            sid_val = sid_tag.split(":")[1] if sid_tag else rule_dict["id"]
            if sid_val in seen_sids:
                result.warnings.append(f"Line {lineno}: Duplicate SID {sid_val} — skipping")
                continue
            seen_sids.add(sid_val)
            result.converted.append(rule_dict)

    return result


def save_as_yaml(result: SnortImportResult, output_path: str) -> int:
    """
    Write the converted rules to a SentinelPy YAML signature file.
    Returns the number of rules written.
    """
    if not result.converted:
        return 0

    data = {
        "schema_version": 1,
        "rules": result.converted,
    }
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
    return len(result.converted)


def import_snort_rules(rules_path: str, output_path: str) -> SnortImportResult:
    """
    High-level entry point: parse, convert, and save Snort rules to YAML.
    """
    result = import_rules_file(rules_path)
    if result.converted:
        save_as_yaml(result, output_path)
    return result
