"""AgentFence Main Application Entrypoint: ASGI REST & MCP Gateway Server
"""
import os
import json
from pathlib import Path
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse, HTMLResponse, FileResponse
from starlette.staticfiles import StaticFiles

from app.core.config import settings
from app.database.session import init_db
from app.database.seed import seed_database
from app.api import routes

# Base paths
FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"

def generate_openapi_spec():
    return {
        "openapi": "3.0.3",
        "info": {
            "title": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "description": settings.DESCRIPTION
        },
        "paths": {
            "/api/v1/health": {
                "get": {"summary": "Health Check", "responses": {"200": {"description": "Gateway status"}}}
            },
            "/api/v1/auth/login": {
                "post": {"summary": "Development Authentication Login", "responses": {"200": {"description": "JWT Access Token"}}}
            },
            "/api/v1/tenants": {
                "get": {"summary": "List All Tenants", "responses": {"200": {"description": "List of tenants"}}}
            },
            "/api/v1/agents": {
                "get": {"summary": "List Registered Agents", "responses": {"200": {"description": "List of agents"}}}
            },
            "/api/v1/tools": {
                "get": {"summary": "List Registered MCP Tools", "responses": {"200": {"description": "List of MCP tools"}}}
            },
            "/api/v1/delegations": {
                "get": {"summary": "List Delegation Grants", "responses": {"200": {"description": "List of delegation grants"}}},
                "post": {"summary": "Create Delegation Grant with Attenuation Verification", "responses": {"200": {"description": "Signed Delegation Credential"}}}
            },
            "/api/v1/policies": {
                "get": {"summary": "List RBAC & ABAC Policies", "responses": {"200": {"description": "List of policies"}}}
            },
            "/api/v1/policies/simulate": {
                "post": {"summary": "Simulate Authorization Decision", "responses": {"200": {"description": "Policy Decision Result"}}}
            },
            "/api/v1/audit/events": {
                "get": {"summary": "Retrieve Live Hash-Linked Audit Events", "responses": {"200": {"description": "Audit events list"}}}
            },
            "/api/v1/audit/verify": {
                "get": {"summary": "Verify Hash-Chain Integrity of Audit Ledger", "responses": {"200": {"description": "Verification report"}}}
            },
            "/api/v1/metrics/overview": {
                "get": {"summary": "Security Metrics & Incident Overview", "responses": {"200": {"description": "Aggregated metrics"}}}
            },
            "/api/v1/simulations/run": {
                "post": {"summary": "Run 10 Attack Scenarios against Security Engine", "responses": {"200": {"description": "Attack simulation results"}}}
            },
            "/mcp/v1/call": {
                "post": {"summary": "Direct Protected MCP Tool Invocation", "responses": {"200": {"description": "Tool Execution Result"}}}
            },
            "/mcp/v1/jsonrpc": {
                "post": {"summary": "Standard MCP JSON-RPC 2.0 Endpoint", "responses": {"200": {"description": "MCP JSON-RPC Response"}}}
            }
        }
    }

async def openapi_json(request):
    return JSONResponse(generate_openapi_spec())

async def swagger_docs(request):
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{settings.PROJECT_NAME} - Interactive API Docs</title>
    <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head>
<body style="margin: 0; background: #0b1120;">
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        window.ui = SwaggerUIBundle({{
            url: '/openapi.json',
            dom_id: '#swagger-ui',
            deepLinking: true,
            presets: [SwaggerUIBundle.presets.apis]
        }});
    </script>
</body>
</html>"""
    return HTMLResponse(html)

# Route definitions
api_routes = [
    Route("/api/v1/health", routes.health, methods=["GET"]),
    Route("/api/v1/auth/login", routes.login, methods=["POST"]),
    Route("/api/v1/tenants", routes.list_tenants, methods=["GET"]),
    Route("/api/v1/tenants/{id}", routes.get_tenant_details, methods=["GET"]),
    Route("/api/v1/agents", routes.list_agents, methods=["GET"]),
    Route("/api/v1/tools", routes.list_tools, methods=["GET"]),
    Route("/api/v1/delegations", routes.list_delegations, methods=["GET"]),
    Route("/api/v1/delegations", routes.create_delegation, methods=["POST"]),
    Route("/api/v1/delegations/revoke/{id}", routes.revoke_delegation, methods=["POST"]),
    Route("/api/v1/policies", routes.list_policies, methods=["GET"]),
    Route("/api/v1/policies/{id}/toggle", routes.toggle_policy, methods=["POST"]),
    Route("/api/v1/policies/simulate", routes.simulate_policy, methods=["POST"]),
    Route("/api/v1/audit/events", routes.list_audit_events, methods=["GET"]),
    Route("/api/v1/audit/verify", routes.verify_audit_integrity, methods=["GET"]),
    Route("/api/v1/metrics/overview", routes.get_security_metrics, methods=["GET"]),
    Route("/api/v1/simulations/run", routes.run_simulations, methods=["POST", "GET"]),
    Route("/api/v1/simulations/results", routes.list_simulation_results, methods=["GET"]),
    Route("/mcp/v1/call", routes.mcp_tool_call, methods=["POST"]),
    Route("/mcp/v1/jsonrpc", routes.mcp_jsonrpc_endpoint, methods=["POST"]),
    Route("/openapi.json", openapi_json, methods=["GET"]),
    Route("/docs", swagger_docs, methods=["GET"]),
]

# Static UI serving (if built)
async def serve_spa(request):
    index_file = FRONTEND_DIST / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse("<h1>AgentFence Security Gateway API Running</h1><p>Visit <a href='/docs'>/docs</a> for interactive OpenAPI documentation.</p>")

if FRONTEND_DIST.exists():
    api_routes.append(Mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="assets"))
api_routes.append(Route("/", serve_spa, methods=["GET"]))

middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=True
    )
]

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app):
    seed_database()
    yield

app = Starlette(
    debug=settings.DEBUG,
    routes=api_routes,
    middleware=middleware,
    lifespan=lifespan
)

if __name__ == "__main__":
    import uvicorn
    print(f"Starting {settings.PROJECT_NAME} Gateway on http://{settings.HOST}:{settings.PORT}")
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
