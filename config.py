from pydantic import BaseModel


class ScanConfig(BaseModel):
    timeout: float = 10.0
    user_agent: str = "AI-API-Security-Analyzer/1.0"
    max_response_preview: int = 800
    verify_tls: bool = True