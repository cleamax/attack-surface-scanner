from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION = "2"

Severity = Literal["low", "medium", "high"]
Risk = Literal["low", "medium", "high"]


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    evidence: str | None = None


class Endpoint(BaseModel):
    url: str
    scheme: Literal["http", "https"]
    final_url: str | None = None
    status_code: int | None = None
    redirect_chain: list[str] = Field(default_factory=list)
    response_ms: int | None = None
    error: str | None = None


class Asset(BaseModel):
    hostname: str
    ip_addresses: list[str] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    reachable: bool = False
    uses_https: bool = False
    http_reachable: bool = False
    redirects_to_https: bool = False
    tls_versions: list[str] = Field(default_factory=list)
    certificate_expires: datetime | None = None
    findings: list[Finding] = Field(default_factory=list)

    risk: Risk = "low"
    risk_reasons: list[str] = Field(default_factory=list)
    risk_score: int = 0


class ScanResult(BaseModel):
    schema_version: str = SCHEMA_VERSION
    scan_id: str
    target_domain: str
    started_at: datetime
    finished_at: datetime | None = None
    duration_seconds: float | None = None

    discovery_source: str = "unknown"
    asset_count: int = 0
    resolved_count: int = 0
    out_of_scope_rejected: int = 0

    warnings: list[str] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)

    risk_summary: dict[str, int] = Field(default_factory=dict)
    finding_summary: dict[str, int] = Field(default_factory=dict)
