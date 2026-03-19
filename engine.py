from models import ScanResult, Finding
from rules import RuleEngine
from scanner import APIScanner
from jwt_analyzer import JWTAnalyzer


class SecurityEngine:
    def __init__(self):
        self.scanner = APIScanner()
        self.rules = RuleEngine()
        self.jwt = JWTAnalyzer()

    def risk_score(self, findings: list[Finding], jwt_issues: list[str]) -> tuple[int, str]:
        score = 0

        severity_weights = {
            "low": 1,
            "medium": 4,
            "high": 8,
            "critical": 12,
        }

        for finding in findings:
            score += severity_weights.get(finding.severity, 0)

        score += len(jwt_issues) * 3

        if score >= 20:
            return score, "critical"
        if score >= 12:
            return score, "high"
        if score >= 6:
            return score, "medium"
        return score, "low"

    async def scan(self, url: str, method: str = "GET", token: str | None = None, body: dict | None = None):
        raw = await self.scanner.request(url, method=method, token=token, body=body)
        findings = self.rules.run(raw)

        jwt_report = None
        jwt_issues = []
        if token:
            jwt_report = self.jwt.analyze(token)
            jwt_issues = jwt_report.get("issues", [])

        score, level = self.risk_score(findings, jwt_issues)

        return ScanResult(
            url=url,
            method=method,
            status_code=raw.get("status_code"),
            response_time_ms=raw.get("response_time_ms"),
            response_length=raw.get("response_length"),
            headers=raw.get("headers", {}),
            preview=raw.get("preview"),
            findings=findings,
            risk_score=score,
            risk_level=level
        ), jwt_report