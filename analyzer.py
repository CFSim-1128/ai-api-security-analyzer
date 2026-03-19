def analyze_response(scan_result):
    issues = []

    if "error" in scan_result:
        return {"risk": "UNKNOWN", "issues": ["Request failed"]}

    # Example checks
    if scan_result["status_code"] == 200:
        issues.append("Endpoint accessible (potential exposure)")

    if "server" in scan_result["headers"]:
        issues.append("Server header exposed")

    if scan_result["response_length"] > 10000:
        issues.append("Large response size (possible data exposure)")

    risk_level = "LOW"

    if len(issues) >= 2:
        risk_level = "MEDIUM"
    if len(issues) >= 3:
        risk_level = "HIGH"

    return {
        "risk": risk_level,
        "issues": issues
    }