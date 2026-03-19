from models import Finding


class RuleEngine:
    def run(self, scan_data: dict) -> list[Finding]:
        findings: list[Finding] = []
        headers = scan_data.get("headers", {})
        status_code = scan_data.get("status_code", 0)
        preview = scan_data.get("preview", "")
        body = scan_data.get("body", "")
        content = f"{preview}\n{body}".lower()

        if status_code == 200:
            findings.append(Finding(
                rule_id="R001",
                title="Endpoint returns HTTP 200",
                severity="low",
                confidence=0.65,
                evidence={"status_code": status_code}
            ))

        if "server" not in headers:
            findings.append(Finding(
                rule_id="R002",
                title="Server header not exposed",
                severity="low",
                confidence=0.80,
                evidence={"headers_checked": ["server"]}
            ))

        if "x-powered-by" in headers:
            findings.append(Finding(
                rule_id="R003",
                title="Technology disclosure via X-Powered-By header",
                severity="medium",
                confidence=0.92,
                evidence={"x-powered-by": headers.get("x-powered-by")}
            ))

        if "traceback" in content or "exception" in content or "stack trace" in content:
            findings.append(Finding(
                rule_id="R004",
                title="Potential verbose error disclosure",
                severity="high",
                confidence=0.88,
                evidence={"preview_match": "error/exception leakage"}
            ))

        if any(marker in content for marker in ["unauthorized", "forbidden", "access denied"]):
            findings.append(Finding(
                rule_id="R005",
                title="Access control response observed",
                severity="low",
                confidence=0.55,
                evidence={"preview_match": "authorization-related response"}
            ))

        return findings