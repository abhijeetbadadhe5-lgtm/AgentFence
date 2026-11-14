"""AgentFence MCP JSON-RPC 2.0 Protocol Handler
Supports standard Model Context Protocol (MCP) version 2024-11-05.
"""
import json
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from app.gateway.interceptor import gateway_interceptor
from app.models.entities import MCPTool

class MCPProtocolHandler:
    PROTOCOL_VERSION = "2024-11-05"

    def __init__(self):
        self.interceptor = gateway_interceptor

    def handle_jsonrpc(
        self,
        db: Session,
        request_data: Dict[str, Any],
        identity_token: Optional[str] = None,
        delegation_token: Optional[str] = None,
        client_audience: Optional[str] = None
    ) -> Dict[str, Any]:
        """Processes a JSON-RPC 2.0 MCP request."""
        req_id = request_data.get("id")
        method = request_data.get("method")
        params = request_data.get("params", {})

        # Handle Protocol Handshake
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": self.PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {
                            "listChanged": False
                        }
                    },
                    "serverInfo": {
                        "name": "AgentFence Security Gateway",
                        "version": "1.0.0",
                        "description": "Delegation-Aware AI Agent Security Gateway"
                    }
                }
            }

        # Notification of initialization complete
        if method == "notifications/initialized":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        # Tool Discovery (tools/list)
        if method == "tools/list":
            tools = db.query(MCPTool).filter(MCPTool.is_enabled == True).all()
            tools_list = []
            for t in tools:
                tools_list.append({
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.get_parameters_schema()
                })
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": tools_list
                }
            }

        # Tool Invocation (tools/call)
        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})

            if not tool_name:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": "Missing 'name' in tools/call params"
                    }
                }

            # Intercept and Authorize
            result = self.interceptor.process_tool_invocation(
                db=db,
                tool_name=tool_name,
                arguments=arguments,
                identity_token=identity_token,
                delegation_token=delegation_token,
                client_audience=client_audience,
                correlation_id=params.get("correlation_id")
            )

            if not result.get("authorized"):
                # Controlled denial response as specified in MCP standard
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "isError": True,
                        "content": result.get("content", [{"type": "text", "text": "Authorization Denied"}]),
                        "decision": result.get("decision"),
                        "reasonCode": result.get("reason_code"),
                        "message": result.get("message")
                    }
                }

            # Return upstream result
            upstream_res = result.get("result", {})
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "isError": upstream_res.get("isError", False),
                    "content": upstream_res.get("content", []),
                    "decision": "ALLOW",
                    "reasonCode": result.get("reason_code")
                }
            }

        # Unknown method
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method '{method}' not found"
            }
        }

mcp_protocol_handler = MCPProtocolHandler()
