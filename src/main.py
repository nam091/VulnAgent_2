from typing import Optional

import uvicorn
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from analyzer.code_analyzer import CodeAnalyzer
from models.vulnerability import VulnerabilityReport
from utils.file_handler import process_uploaded_file

app = FastAPI(
    title="VulnAgent - AI SAST",
    description="AI-powered security vulnerability detection and remediation",
    version="0.1.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalysisRequest(BaseModel):
    repository_url: Optional[str] = None
    branch: Optional[str] = "main"
    scan_depth: Optional[int] = 3

@app.post("/analyze/file", response_model=VulnerabilityReport)
async def analyze_file(file: UploadFile = File(...)) -> VulnerabilityReport:
    """
    Analyze a single file for security vulnerabilities

    Args:
        file: The file to analyze

    Returns:
        VulnerabilityReport: The vulnerability report
    """

    try:
        file_content = await process_uploaded_file(file)
        analyzer = CodeAnalyzer()
        report = await analyzer.analyze_code(file_content, file.filename)
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/repository", response_model=VulnerabilityReport)
async def analyze_repository(request: AnalysisRequest) -> VulnerabilityReport:
    """
    Analyze a git repository for security vulnerabilities

    Args:
        request: The analysis request

    Returns:
        VulnerabilityReport: The vulnerability report
    """

    try:
        analyzer = CodeAnalyzer()
        report = await analyzer.analyze_repository(
            request.repository_url,
            request.branch,
            request.scan_depth
        )
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check() -> dict:
    """
    Health check endpoint
    """

    return {"status": "healthy"}

def main():
    # Run the FastAPI app
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
