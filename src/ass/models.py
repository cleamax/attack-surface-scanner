from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Literal
from pydantic import BaseModel, Field


Severity = Literal["low", "medium", "high"]


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    evidence: Optional[str] = None


class Endpoint(BaseModel):
    url: str
    final_url: Optional[str] = None
    status_code: Optional[int] = None
    redirect_chain: List[str] = Field(default_factory=list)
    response_ms: Optional[int] = None


class Asset(BaseModel):
    hostname: str
    ip_addresses: List[str] = Field(default_factory=list)
    endpoints: List[Endpoint] = Field(default_factory=list)
    reachable: bool = False
    uses_https: bool = False
    findings: List[Finding] = Field(default_factory=list)


class ScanResult(BaseModel):
    scan_id: str
    target_domain: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    asset_count: int = 0
    assets: List[Asset] = Field(default_factory=list)