from pydantic import BaseModel, HttpUrl
from typing import Any, Literal, Optional


class ScanRequest(BaseModel):
    url: HttpUrl
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    token: Optional[str] = None
    body: Optional[dict[str, Any]] = None


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float
    evidence: dict[str, Any]


class ScanResult(BaseModel):
    url: str
    method: str
    status_code: int | None = None
    response_time_ms: float | None = None
    response_length: int | None = None
    headers: dict[str, str] = {}
    preview: str | None = None
    findings: list[Finding] = []
    risk_score: int = 0
    risk_level: str = "low"