"""
SentinelPy IDS - Network File Extraction Engine
Reconstructs files from TCP streams by buffering per-flow payload bytes,
detecting file magic bytes, and writing extracted files to disk.

Supports detection of:
  PDF, ZIP, EXE/DLL (PE), JPEG, PNG, GIF, DOCX/XLSX/PPTX (ZIP-based Office),
  RAR, 7-Zip, TAR.GZ, TAR.BZ2, ELF (Linux binary), Class (Java), SWF, MP3, MP4

Extracted files are saved to the configured output directory and an alert is
generated for each extraction so the SOC analyst can review them.
"""

import os
import time
import threading
import logging
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass, field

logger = logging.getLogger("sentinelpy.extraction")

# ---------------------------------------------------------------------------
# File signature (magic bytes) database
# ---------------------------------------------------------------------------
FILE_SIGNATURES: List[Tuple[bytes, str, str]] = [
    # (magic_bytes_prefix, file_type_name, extension)
    (b"%PDF",                   "PDF Document",          "pdf"),
    (b"PK\x03\x04",            "ZIP Archive",           "zip"),
    (b"MZ",                    "PE Executable/DLL",     "exe"),
    (b"\xff\xd8\xff",          "JPEG Image",            "jpg"),
    (b"\x89PNG\r\n\x1a\n",    "PNG Image",             "png"),
    (b"GIF87a",                "GIF Image",             "gif"),
    (b"GIF89a",                "GIF Image",             "gif"),
    (b"Rar!\x1a\x07",         "RAR Archive",           "rar"),
    (b"\x1f\x8b",             "GZIP / TAR.GZ",         "gz"),
    (b"BZh",                   "BZIP2 / TAR.BZ2",      "bz2"),
    (b"7z\xbc\xaf\x27\x1c",  "7-Zip Archive",         "7z"),
    (b"\x7fELF",              "ELF Linux Binary",      "elf"),
    (b"\xca\xfe\xba\xbe",    "Java Class File",        "class"),
    (b"CWS",                   "SWF Flash",             "swf"),
    (b"FWS",                   "SWF Flash",             "swf"),
    (b"ID3",                   "MP3 Audio",             "mp3"),
    (b"\xff\xfb",             "MP3 Audio",             "mp3"),
    (b"\x00\x00\x00\x14ftyp", "MP4 Video",             "mp4"),
    (b"\x00\x00\x00\x18ftyp", "MP4 Video",             "mp4"),
    (b"RIFF",                  "WAV/AVI Media",         "riff"),
    (b"\xd0\xcf\x11\xe0",    "MS Office OLE (DOC/XLS)", "doc"),
    (b"<!DOCTYPE html",        "HTML Document",         "html"),
    (b"<html",                 "HTML Document",         "html"),
    (b"\x4d\x4d\x00\x2a",    "TIFF Image",            "tif"),
    (b"\x49\x49\x2a\x00",    "TIFF Image",            "tif"),
]

_MAX_PREFIX = max(len(sig[0]) for sig in FILE_SIGNATURES)


def detect_file_type(data: bytes) -> Optional[Tuple[str, str]]:
    """
    Inspect the first bytes of data and return (type_name, extension) or None.
    """
    for magic, name, ext in FILE_SIGNATURES:
        if data[:len(magic)] == magic:
            return name, ext
    return None


# ---------------------------------------------------------------------------
# Per-flow buffer
# ---------------------------------------------------------------------------
@dataclass
class FlowBuffer:
    flow_key: str
    src_ip: str
    dst_ip: str
    protocol: str
    data: bytearray = field(default_factory=bytearray)
    file_detected: bool = False
    file_type: str = ""
    file_ext: str = ""
    started_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def append(self, payload: bytes):
        self.data.extend(payload)
        self.last_seen = time.time()

    def size(self) -> int:
        return len(self.data)


# ---------------------------------------------------------------------------
# File Extractor
# ---------------------------------------------------------------------------
class FileExtractor:
    """
    Buffers per-flow TCP payloads and extracts detected files to disk.
    Thread-safe for use with the SentinelEngine processing loop.
    """

    def __init__(
        self,
        output_dir: str = "extractions",
        max_file_size_bytes: int = 10 * 1024 * 1024,   # 10 MB per file
        min_detect_bytes: int = 32,                      # must have at least this many bytes to detect
        flow_idle_timeout: float = 30.0,                 # seconds before a flow buffer is flushed
        enabled: bool = True,
    ):
        self.output_dir         = output_dir
        self.max_file_size      = max_file_size_bytes
        self.min_detect_bytes   = min_detect_bytes
        self.flow_idle_timeout  = flow_idle_timeout
        self.enabled            = enabled
        self._buffers: Dict[str, FlowBuffer] = {}
        self._lock              = threading.Lock()
        self._extractions: List[Dict] = []  # metadata log

        if enabled:
            os.makedirs(output_dir, exist_ok=True)

    def observe(self, flow_key: str, src_ip: str, dst_ip: str,
                protocol: str, payload: bytes) -> Optional[Dict]:
        """
        Feed a payload chunk for a flow. Returns extraction metadata dict if a
        file was just extracted, else None.
        """
        if not self.enabled or not payload:
            return None

        with self._lock:
            buf = self._buffers.get(flow_key)
            if buf is None:
                buf = FlowBuffer(flow_key=flow_key, src_ip=src_ip,
                                 dst_ip=dst_ip, protocol=protocol)
                self._buffers[flow_key] = buf

            # Cap at max size
            remaining = self.max_file_size - buf.size()
            if remaining <= 0:
                return None
            buf.append(payload[:remaining])

            # Try to detect a file type once we have enough bytes
            if not buf.file_detected and buf.size() >= self.min_detect_bytes:
                result = detect_file_type(bytes(buf.data))
                if result:
                    buf.file_detected = True
                    buf.file_type, buf.file_ext = result

            # Flush and extract when buffer hits max or file already detected
            # and no more growth expected — we trigger on max_size or idle
            if buf.file_detected and buf.size() >= self.max_file_size:
                return self._flush_buffer(flow_key)

        return None

    def flush_idle(self) -> List[Dict]:
        """
        Flush all flow buffers that have been idle for > flow_idle_timeout.
        Call periodically (e.g. every 10 s) from a background thread.
        Returns list of extraction metadata dicts.
        """
        now = time.time()
        extracted = []
        with self._lock:
            idle_keys = [
                k for k, b in self._buffers.items()
                if now - b.last_seen > self.flow_idle_timeout
            ]
        for key in idle_keys:
            result = self._flush_buffer(key)
            if result:
                extracted.append(result)
        return extracted

    def flush_all(self) -> List[Dict]:
        """Flushes all buffered flows immediately to disk (useful on shutdown/tests)."""
        extracted = []
        with self._lock:
            keys = list(self._buffers.keys())
        for key in keys:
            result = self._flush_buffer(key)
            if result:
                extracted.append(result)
        return extracted

    def _flush_buffer(self, flow_key: str) -> Optional[Dict]:
        """Write buffer to disk if a file was detected. Must be called under lock or with care."""
        buf = self._buffers.pop(flow_key, None)
        if not buf or not buf.file_detected or buf.size() < self.min_detect_bytes:
            return None

        ts = int(buf.started_at)
        safe_key = flow_key.replace(":", "_").replace("<->", "_vs_").replace("/", "_")
        filename = f"{ts}_{safe_key}.{buf.file_ext}"
        filepath = os.path.join(self.output_dir, filename)

        try:
            with open(filepath, "wb") as f:
                f.write(bytes(buf.data))
        except Exception as exc:
            logger.error("Failed to write extracted file %s: %s", filepath, exc)
            return None

        metadata = {
            "file_path":  filepath,
            "file_type":  buf.file_type,
            "file_ext":   buf.file_ext,
            "size_bytes": buf.size(),
            "flow_key":   flow_key,
            "src_ip":     buf.src_ip,
            "dst_ip":     buf.dst_ip,
            "protocol":   buf.protocol,
            "extracted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self._extractions.append(metadata)
        logger.info(
            "FILE EXTRACTED: %s | type=%s | size=%d bytes | flow=%s",
            filepath, buf.file_type, buf.size(), flow_key
        )
        return metadata

    def total_extracted(self) -> int:
        return len(self._extractions)

    def get_extractions(self) -> List[Dict]:
        return list(self._extractions)

    def active_flows(self) -> int:
        with self._lock:
            return len(self._buffers)
