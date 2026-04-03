"""
AegisCore — FastAPI Backend
Serves classified log alerts and dashboard statistics.
"""

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect, BackgroundTasks, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import os
import asyncio
import json
import pandas as pd
from contextlib import asynccontextmanager

from log_parser import load_all_logs
from classifier import classify_all, classify_single, get_stats
from datetime import datetime

# ─────────────────────────────────────────────────────────────
# Initialize & Classify on Startup
# ─────────────────────────────────────────────────────────────
print("\n" + "═" * 60)
print("  🛡️  AEGISCORE DASHBOARD — SOC Alert Classification Engine (LIVE TRAFFIC)")
print("═" * 60 + "\n")

ALL_ALERTS = []
STATS = {}
PROCESSING_DONE = True  # Setup for realtime processing
IS_PROCESSING = False

print(f"\n[AegisCore] Real-time traffic sniffer ready.\n")

# ─────────────────────────────────────────────────────────────
# FastAPI App & WebSockets
# ─────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Dataset process triggered manually via API now
    yield

app = FastAPI(
    title="AegisCore — SOC Dashboard",
    description="AI-Powered Security Operations Center Alert Classification (Async)",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_alert(self, alert: dict):
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps({"type": "alert", "data": alert}))
            except Exception:
                pass
                
    async def broadcast_stats(self, stats: dict):
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps({"type": "stats", "data": stats}))
            except Exception:
                pass

manager = ConnectionManager()


# ─────────────────────────────────────────────────────────────
# Async Background Worker
# ─────────────────────────────────────────────────────────────
# Background processing is deprecated; Traffic intercepted in real-time via Middleware

@app.middleware("http")
async def traffic_interceptor(request: Request, call_next):
    # Process request to simulate packet sniffing realtime
    response = await call_next(request)
    
    # Try logging traffic asynchronously to avoid blocking
    if "api/alerts" in request.url.path or "api/stats" in request.url.path or "/ws/" in request.url.path or request.url.path in ["/styles.css", "/dashboard", "/login", "/"]:
        # Do not log the dashboard's own API fetches
        return response
        
    client_ip = request.headers.get("x-simulated-ip", request.client.host if request.client else "127.0.0.1")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    content_str = f"HTTP {request.method} {request.url.path}"
    
    row = {
        "id": len(ALL_ALERTS) + 1,
        "timestamp": timestamp,
        "source_os": request.headers.get("x-target-os", "Unknown"),
        "component": f"{request.method} {request.url.path}",
        "content": content_str,
        "source_ip": client_ip,
        "raw_headers": dict(request.headers),
        "level": "info"
    }
    
    alert = classify_single(row)
    
    ALL_ALERTS.insert(0, alert)  # Add at the top for real-time feed
    if len(ALL_ALERTS) > 3000:
        ALL_ALERTS.pop()
        
    global STATS
    STATS = get_stats(ALL_ALERTS)
    
    asyncio.create_task(manager.broadcast_stats(STATS))
    asyncio.create_task(manager.broadcast_alert(alert))
        
    return response

# ─────────────────────────────────────────────────────────────
# API Endpoints
# ─────────────────────────────────────────────────────────────

@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send initial stats
        await websocket.send_text(json.dumps({"type": "stats", "data": STATS}))
        while True:
            # Keep alive
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/api/alerts")
async def get_alerts(
    severity: str | None = Query(None, description="Filter by severity: Critical, High, Medium, Low"),
    category: str | None = Query(None, description="Filter by category: Malicious, Suspicious, Benign"),
    source: str | None = Query(None, description="Filter by OS: Linux, Windows, macOS"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(100, ge=1, le=1000, description="Results per page"),
):
    """Return classified alerts with optional filters and pagination."""
    filtered = ALL_ALERTS

    if severity:
        filtered = [a for a in filtered if a["severity"].lower() == severity.lower()]
    if category:
        filtered = [a for a in filtered if a["category"].lower() == category.lower()]
    if source:
        filtered = [a for a in filtered if a["source_os"].lower() == source.lower()]

    # Pagination
    start = (page - 1) * limit
    end = start + limit
    page_alerts = filtered[start:end]

    return {
        "total": len(filtered),
        "page": page,
        "limit": limit,
        "pages": (len(filtered) + limit - 1) // limit if limit > 0 else 0,
        "alerts": page_alerts,
        "processing_done": PROCESSING_DONE
    }

@app.get("/api/stats")
async def get_dashboard_stats():
    """Return aggregate dashboard statistics."""
    return STATS

@app.get("/api/alerts/critical")
async def get_critical_alerts():
    """Return only High and Critical alerts for AegisCore overlay."""
    critical = [a for a in ALL_ALERTS if a["severity"] in ("Critical", "High")]
    return {
        "total": len(critical),
        "alerts": critical[:50],  # Top 50 most severe
    }


# ─────────────────────────────────────────────────────────────
# Static Files & Dashboard
# ─────────────────────────────────────────────────────────────

STATIC_DIR = os.path.dirname(os.path.abspath(__file__))


@app.get("/")
def redirect_to_login():
    """Redirect to login page."""
    return RedirectResponse(url="/login")

@app.get("/login")
def serve_login():
    """Serve the login gateway."""
    return FileResponse(os.path.join(STATIC_DIR, "login.html"))

@app.post("/api/auth")
async def authenticate(request: Request):
    """Basic mock authentication."""
    data = await request.json()
    if data.get("username") == "admin" and data.get("password") == "password123":
        return JSONResponse(content={"status": "success"})
    return JSONResponse(status_code=401, content={"status": "unauthorized"})

@app.get("/logout")
def logout():
    """Handle user logout."""
    return RedirectResponse(url="/login", status_code=303)

@app.post("/api/ingest")
async def ingest_logs(request: Request):
    """Handle log file ingestion."""
    # In a real scenario, use UploadFile
    return JSONResponse(content={"status": "success", "message": "Log ingestion started"})

@app.get("/dashboard")
def serve_dashboard():
    """Serve the main dashboard."""
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))

@app.post("/api/start-scan")
async def trigger_scan():
    """Trigger the live background analysis (Deprecated - Live natively)."""
    return {"status": "started"}


@app.get("/styles.css")
def serve_styles():
    """Serve custom CSS."""
    return FileResponse(
        os.path.join(STATIC_DIR, "styles.css"),
        media_type="text/css"
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
