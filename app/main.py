from fastapi import FastAPI

from app.api.routes_alerts import router as alerts_router
from app.api.routes_dashboard import router as dashboard_router
from app.api.routes_health import router as health_router
from app.api.routes_metrics import router as metrics_router
from app.api.routes_reports import router as reports_router
from app.api.routes_reset import router as reset_router

from app.database import Base, engine

app = FastAPI(title="Smart SIEM Risk Engine API", version="1.0.0")


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


init_db()

from fastapi.responses import RedirectResponse

@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/dashboard")

app.include_router(health_router, tags=["Health"])
app.include_router(alerts_router, tags=["Alerts"])
app.include_router(metrics_router, tags=["Metrics"])
app.include_router(reports_router, tags=["Reports"])
app.include_router(dashboard_router, tags=["Dashboard"])
app.include_router(reset_router, tags=["Reset"])

import httpx
import uuid
from fastapi import Request, Response, HTTPException

TARGET_URL = "http://httpbingo.org"

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def reverse_proxy(request: Request, path: str):
    # Do not proxy API or Dashboard routes
    if path.startswith("api/") or path.startswith("dashboard") or path.startswith("static"):
        raise HTTPException(status_code=404, detail="Route not found")
        
    ip = request.client.host
    method = request.method
    from urllib.parse import unquote
    raw_query = f"/{path}?{request.url.query}" if request.url.query else f"/{path}"
    url_query = unquote(raw_query).lower()
    user_agent = request.headers.get("user-agent", "").lower()
    
    # 1. Simple Heuristic IPS Check
    is_malicious = False
    attack_type = "Unknown"
    mitre_id = []
    
    if "union select" in url_query or "drop table" in url_query or "1=1" in url_query:
        is_malicious, attack_type, mitre_id = True, "SQL Injection", ["T1190"]
    elif "<script>" in url_query or "javascript:" in url_query or "onload=" in url_query:
        is_malicious, attack_type, mitre_id = True, "Cross-Site Scripting (XSS)", ["T1189"]
    elif "nmap" in user_agent or "dirbuster" in user_agent:
         is_malicious, attack_type, mitre_id = True, "Automated Scanner", ["T1595"]

    if is_malicious:
        # Broadcast the blocked alert to the Smart SIEM dashboard
        alert_id = str(uuid.uuid4())
        alert_html = f"""
        <tr class="alert-row highlight-new">
            <td class="mono id-cell" title="New Alert" style="color:red; font-weight:bold">*PROXY BLOCK*</td>
            <td class="mono id-cell" title="{alert_id}">{alert_id[:8]}...</td>
            <td class="mono score-renderer" data-score="100">100/100</td>
            <td>
                <span class="badge badge-action badge-block">
                    BLOCK_AND_REPORT
                </span>
            </td>
            <td style="color: var(--text-secondary); font-size: 0.8125rem;">
                Intercepted {attack_type} from {ip}
            </td>
        </tr>
        """
        payload = {
            "alert_html": alert_html,
            "risk_score": 100,
            "recommended_action": "BLOCK_AND_REPORT",
            "action_taken": "blocked_at_proxy",
            "mitre_ids": mitre_id,
        }
        # Fire internally to websocket broadcaster
        try:
            async with httpx.AsyncClient() as c:
                await c.post("http://127.0.0.1:8000/api/internal/broadcast", json=payload, timeout=1.0)
        except Exception:
            pass

        return Response(
            content="<html><body><h1 style='color:red;'>403 Forbidden</h1><h3>Malicious request intercepted by Shield.io SIEM proxy.</h3></body></html>",
            status_code=403
        )
    
    # 2. Forward clean traffic upstream
    async with httpx.AsyncClient() as client:
        target_req_url = f"{TARGET_URL}/{path}?{request.url.query}" if request.url.query else f"{TARGET_URL}/{path}"
        forward_headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}
        try:
            proxy_req = client.build_request(method=request.method, url=target_req_url, headers=forward_headers, content=await request.body())
            proxy_res = await client.send(proxy_req)
            res_headers = dict(proxy_res.headers)
            if "content-encoding" in res_headers: del res_headers["content-encoding"]
            return Response(content=proxy_res.content, status_code=proxy_res.status_code, headers=res_headers)
        except Exception as e:
            return Response(content=f"Error reaching upstream: {e}", status_code=502)