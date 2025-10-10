"""
FastAPI Backend for Google Workspace Log Analyzer Web UI

Provides REST API endpoints for:
- Google OAuth authentication
- Log fetching and enrichment
- Multi-agent analysis execution
- Analysis results retrieval
"""

import os
import sys
import json
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from dotenv import load_dotenv

# Add parent directories to path to import existing modules
sys.path.append(str(Path(__file__).parent.parent.parent))
from fetch_logs import WorkspaceLogFetcher
from orchestrator_modular import ModularAnalysisOrchestrator
from report_aggregator import ReportAggregator

load_dotenv()

app = FastAPI(title="Workspace Log Analyzer API", version="1.0.0")

# CORS middleware for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Vite default port
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OAuth configuration
SCOPES = [
    'https://www.googleapis.com/auth/admin.reports.audit.readonly',
    'https://www.googleapis.com/auth/admin.directory.user.readonly',
    'https://www.googleapis.com/auth/admin.directory.device.mobile.readonly',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'openid'
]

REDIRECT_URI = "http://localhost:8000/auth/callback"

# In-memory session storage (for development only)
# In production, use Redis or database
sessions: Dict[str, Dict[str, Any]] = {}


# Pydantic models
class AuthResponse(BaseModel):
    access_token: str
    user_email: str
    workspace_domain: str


class LogFetchRequest(BaseModel):
    hours_back: int = 24


class LogFetchResponse(BaseModel):
    log_file_path: str
    total_events: int
    metadata: Dict[str, Any]


class AnalysisRequest(BaseModel):
    log_file_path: str


class AnalysisResponse(BaseModel):
    analysis_file_path: str
    total_anomalies: int
    actual_risks: int
    summary: Dict[str, Any]


# Helper functions
def get_credentials_file_path():
    """Get the path to credentials.json from parent directory."""
    return str(Path(__file__).parent.parent.parent / "credentials.json")


def create_flow():
    """Create OAuth flow instance."""
    credentials_path = get_credentials_file_path()
    if not os.path.exists(credentials_path):
        raise HTTPException(
            status_code=500,
            detail=f"credentials.json not found at {credentials_path}"
        )

    flow = Flow.from_client_secrets_file(
        credentials_path,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    return flow


def get_user_session(token: str):
    """Get user session from token."""
    if token not in sessions:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return sessions[token]


# Auth endpoints
@app.get("/auth/login")
async def login():
    """Initiate Google OAuth flow."""
    flow = create_flow()
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )

    # Store state for validation
    sessions[state] = {"state": state, "flow_created": datetime.now().isoformat()}

    return {"authorization_url": authorization_url, "state": state}


@app.get("/auth/callback")
async def auth_callback(code: str, state: str):
    """Handle OAuth callback from Google."""
    if state not in sessions:
        raise HTTPException(status_code=400, detail="Invalid state parameter")

    try:
        flow = create_flow()
        flow.fetch_token(code=code)

        credentials = flow.credentials

        # Get user info
        from googleapiclient.discovery import build
        user_service = build('oauth2', 'v2', credentials=credentials)
        user_info = user_service.userinfo().get().execute()

        user_email = user_info.get('email')
        workspace_domain = user_email.split('@')[1] if '@' in user_email else None

        # Create session token (in production, use JWT)
        import secrets
        session_token = secrets.token_urlsafe(32)

        sessions[session_token] = {
            "credentials": credentials_to_dict(credentials),
            "user_email": user_email,
            "workspace_domain": workspace_domain,
            "created_at": datetime.now().isoformat()
        }

        # Remove state session
        del sessions[state]

        # Redirect to frontend with token
        return RedirectResponse(
            url=f"http://localhost:5173/auth-success?token={session_token}"
        )

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Authentication failed: {str(e)}")


@app.get("/auth/me")
async def get_current_user(token: str = Query(...)):
    """Get current authenticated user info."""
    session = get_user_session(token)
    return {
        "user_email": session["user_email"],
        "workspace_domain": session["workspace_domain"]
    }


# Log fetching endpoints
@app.post("/api/logs/fetch", response_model=LogFetchResponse)
async def fetch_logs(
    request: LogFetchRequest,
    token: str = Query(...)
):
    """Fetch authentication logs from Google Workspace."""
    session = get_user_session(token)

    try:
        # Recreate credentials from session
        creds = Credentials(**session["credentials"])

        # Check if credentials are expired and refresh if needed
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            session["credentials"] = credentials_to_dict(creds)

        # Save credentials temporarily for fetcher
        temp_token_path = Path(__file__).parent / f"temp_token_{token[:8]}.json"
        with open(temp_token_path, 'w') as f:
            f.write(creds.to_json())

        # Fetch logs using existing module
        fetcher = WorkspaceLogFetcher(
            credentials_file=get_credentials_file_path(),
            token_file=str(temp_token_path)
        )

        # Authenticate the fetcher
        fetcher.authenticate()

        raw_logs = fetcher.fetch_login_logs(hours_back=request.hours_back)
        processed_logs = fetcher.process_logs(raw_logs)

        # Save logs to parent logs directory
        logs_dir = Path(__file__).parent.parent.parent / "logs"
        log_file_path = fetcher.save_logs(
            processed_logs,
            output_dir=str(logs_dir),
            hours_back=request.hours_back
        )

        # Clean up temp token
        temp_token_path.unlink(missing_ok=True)

        # Load metadata from saved file
        with open(log_file_path, 'r') as f:
            log_data = json.load(f)

        return LogFetchResponse(
            log_file_path=log_file_path,
            total_events=len(processed_logs),
            metadata=log_data.get('metadata', {})
        )

    except Exception as e:
        import traceback
        print(f"ERROR in fetch_logs: {str(e)}")
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Failed to fetch logs: {str(e)}")


@app.get("/api/logs/{log_filename}")
async def get_log_details(log_filename: str, token: str = Query(...)):
    """Get details of a specific log file."""
    get_user_session(token)  # Validate token

    logs_dir = Path(__file__).parent.parent.parent / "logs"
    log_path = logs_dir / log_filename

    if not log_path.exists():
        raise HTTPException(status_code=404, detail="Log file not found")

    with open(log_path, 'r') as f:
        return json.load(f)


# Analysis endpoints
@app.post("/api/analysis/run", response_model=AnalysisResponse)
async def run_analysis(
    request: AnalysisRequest,
    token: str = Query(...)
):
    """Run automated multi-agent analysis on log file."""
    get_user_session(token)  # Validate token

    if not os.path.exists(request.log_file_path):
        raise HTTPException(status_code=404, detail="Log file not found")

    try:
        # Run orchestrator
        analysis_dir = Path(__file__).parent.parent.parent / "analysis"
        orchestrator = ModularAnalysisOrchestrator(
            request.log_file_path,
            output_dir=str(analysis_dir)
        )
        results = orchestrator.run_analysis(enable_tier2=True)

        # Extract analysis file path - modular orchestrator saves to reports/
        # Find the most recent report file
        reports_dir = analysis_dir / "reports"
        report_files = sorted(reports_dir.glob("final_report_*.json"), reverse=True)
        analysis_file = report_files[0] if report_files else analysis_dir / "reports" / "final_report.json"

        # Map modular orchestrator output to expected API format
        tier1_anomalies = results.get('tier1_anomalies', [])
        tier2_analyses = results.get('tier2_analyses', [])
        summary_data = results.get('summary', {})

        # Count actual risks from tier2 analyses
        actual_risks = sum(1 for a in tier2_analyses if a.get('is_actual_risk', False))

        return AnalysisResponse(
            analysis_file_path=str(analysis_file),
            total_anomalies=summary_data.get('tier1_detections', len(tier1_anomalies)),
            actual_risks=actual_risks,
            summary={
                'total_initial_detections': summary_data.get('tier1_detections', 0),
                'total_refined_anomalies': summary_data.get('tier2_analyses_performed', 0),
                'actual_risks': actual_risks,
                'false_positives_filtered': summary_data.get('false_positives_filtered', 0),
                'severity_breakdown': summary_data.get('severity_breakdown', {})
            }
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/api/analysis/{analysis_filename}")
async def get_analysis_details(analysis_filename: str, token: str = Query(...)):
    """Get details of a specific analysis file."""
    get_user_session(token)  # Validate token

    analysis_dir = Path(__file__).parent.parent.parent / "analysis"
    analysis_path = analysis_dir / analysis_filename

    if not analysis_path.exists():
        raise HTTPException(status_code=404, detail="Analysis file not found")

    with open(analysis_path, 'r') as f:
        return json.load(f)


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


# Helper function
def credentials_to_dict(credentials):
    """Convert credentials object to dictionary."""
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
