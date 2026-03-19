from fastapi import FastAPI, HTTPException
from models import ScanRequest
from engine import SecurityEngine

app = FastAPI(title="AI API Security Analyzer", version="2.0")
engine = SecurityEngine()


@app.get("/")
async def home():
    return {"message": "AI API Security Analyzer is running"}


@app.post("/scan")
async def scan_api(req: ScanRequest):
    try:
        result, jwt_report = await engine.scan(
            url=str(req.url),
            method=req.method,
            token=req.token,
            body=req.body
        )
        return {
            "scan": result.model_dump(),
            "jwt": jwt_report
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))