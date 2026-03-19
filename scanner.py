import time
import httpx
from config import ScanConfig


class APIScanner:
    def __init__(self, config: ScanConfig | None = None):
        self.config = config or ScanConfig()

    async def request(self, url: str, method: str = "GET", token: str | None = None, body: dict | None = None):
        headers = {"User-Agent": self.config.user_agent}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        async with httpx.AsyncClient(timeout=self.config.timeout, verify=self.config.verify_tls, follow_redirects=True) as client:
            start = time.perf_counter()

            if method == "GET":
                resp = await client.get(url, headers=headers)
            elif method == "POST":
                resp = await client.post(url, headers=headers, json=body or {})
            elif method == "PUT":
                resp = await client.put(url, headers=headers, json=body or {})
            elif method == "PATCH":
                resp = await client.patch(url, headers=headers, json=body or {})
            elif method == "DELETE":
                resp = await client.delete(url, headers=headers)
            else:
                raise ValueError("Unsupported HTTP method")

            elapsed = (time.perf_counter() - start) * 1000

        return {
            "status_code": resp.status_code,
            "response_time_ms": round(elapsed, 2),
            "response_length": len(resp.text),
            "headers": {k.lower(): v for k, v in resp.headers.items()},
            "preview": resp.text[: self.config.max_response_preview],
            "body": resp.text,
        }