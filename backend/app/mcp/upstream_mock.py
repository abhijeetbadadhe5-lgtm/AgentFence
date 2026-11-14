"""AgentFence Upstream Sample MCP Server Implementation
Executes approved tool calls for authorized agents.
"""
from typing import Dict, Any
from sqlalchemy.orm import Session
from app.models.entities import ProtectedResource

class UpstreamMCPServer:
    """Mock/Demonstration upstream MCP tool execution service."""

    def execute_tool(self, db: Session, tool_name: str, arguments: Dict[str, Any], tenant_id: str) -> Dict[str, Any]:
        """Executes a tool on behalf of an authorized agent."""
        if tool_name == "read_document":
            resource_id = arguments.get("resource_id")
            if not resource_id:
                return {"isError": True, "content": [{"type": "text", "text": "Missing 'resource_id' parameter"}]}
            
            res = db.query(ProtectedResource).filter(
                ProtectedResource.id == resource_id,
                ProtectedResource.tenant_id == tenant_id
            ).first()

            if not res:
                return {"isError": True, "content": [{"type": "text", "text": f"Document '{resource_id}' not found in tenant perimeter"}]}

            return {
                "isError": False,
                "content": [
                    {
                        "type": "text",
                        "text": f"Document Name: {res.name}\nClassification: {res.sensitivity_level.upper()}\nContent: {res.content}"
                    }
                ]
            }

        elif tool_name == "search_knowledge_base":
            query = arguments.get("query", "").lower()
            limit = int(arguments.get("limit", 5))

            docs = db.query(ProtectedResource).filter(ProtectedResource.tenant_id == tenant_id).all()
            matched = []
            for d in docs:
                if query in d.name.lower() or query in d.content.lower():
                    matched.append({"id": d.id, "title": d.name, "sensitivity": d.sensitivity_level})
                if len(matched) >= limit:
                    break

            return {
                "isError": False,
                "content": [
                    {
                        "type": "text",
                        "text": f"Search Results for '{query}': Found {len(matched)} matching records: {matched}"
                    }
                ]
            }

        elif tool_name == "execute_analytics_query":
            qtype = arguments.get("query_type", "aggregate")
            dataset = arguments.get("dataset_id", "primary")
            return {
                "isError": False,
                "content": [
                    {
                        "type": "text",
                        "text": f"Analytics Query Executed ({qtype}) on Dataset ({dataset}): 4,892 records processed. Variance: 0.041. P99: 142ms."
                    }
                ]
            }

        elif tool_name == "export_tenant_report":
            fmt = arguments.get("report_format", "json")
            return {
                "isError": False,
                "content": [
                    {
                        "type": "text",
                        "text": f"Audit Report Generated for Tenant '{tenant_id}' in format '{fmt}'. Hash: a3f98c11e..."
                    }
                ]
            }

        elif tool_name == "admin_override":
            action = arguments.get("action", "diagnostics")
            return {
                "isError": False,
                "content": [
                    {
                        "type": "text",
                        "text": f"ADMIN OVERRIDE EXECUTED: Action '{action}' completed."
                    }
                ]
            }

        else:
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Upstream tool '{tool_name}' not implemented"}]
            }

upstream_mcp_server = UpstreamMCPServer()
