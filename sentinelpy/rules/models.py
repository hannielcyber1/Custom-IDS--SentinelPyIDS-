"""
SentinelPy IDS - Rule Schema Models
Defines Pydantic models for signature and behavioral rules.
"""

from typing import List, Optional, Union, Dict, Any
from pydantic import BaseModel, Field

class ContentMatch(BaseModel):
    any_of: Optional[List[str]] = None
    exact: Optional[str] = None
    nocase: bool = True

class TcpFlagsMatch(BaseModel):
    contains: Optional[str] = None
    exact: Optional[str] = None

class SignatureMatch(BaseModel):
    protocol: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    destination_ports: Optional[List[int]] = None
    ports: Optional[List[int]] = None
    tcp_flags: Optional[Union[str, TcpFlagsMatch]] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    content: Optional[Union[str, ContentMatch]] = None
    regex: Optional[str] = None
    magic_bytes: Optional[str] = None
    tls_sni: Optional[Union[str, List[str]]] = None
    # --- JA3 TLS fingerprint matching ---
    ja3: Optional[str] = None
    ja3_list: Optional[List[str]] = None
    # --- HTTP protocol fields ---
    http_uri: Optional[str] = None
    http_user_agent: Optional[str] = None
    http_method: Optional[str] = None
    # --- GeoIP country filter ---
    geoip_country: Optional[Union[str, List[str]]] = None
    # --- Flowbits stateful detection ---
    flowbits_isset: Optional[str] = None
    flowbits_set: Optional[str] = None

class SignatureRule(BaseModel):
    id: str
    name: str
    enabled: bool = True
    category: str = "general"
    severity: str = Field(default="medium", pattern="^(informational|low|medium|high|critical)$")
    match: SignatureMatch
    description: str = ""
    tags: List[str] = Field(default_factory=list)

class BehavioralScope(BaseModel):
    source: str = "source_ip"
    destination: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None

class BehavioralRule(BaseModel):
    id: str
    name: str
    enabled: bool = True
    category: str = "behavioral"
    severity: str = Field(default="medium", pattern="^(informational|low|medium|high|critical)$")
    detector: str
    scope: BehavioralScope = Field(default_factory=BehavioralScope)
    window_seconds: int = 10
    threshold: Dict[str, Any] = Field(default_factory=dict)
    description: str = ""
    tags: List[str] = Field(default_factory=list)

class RuleFile(BaseModel):
    schema_version: int = 1
    rules: List[Dict[str, Any]]
