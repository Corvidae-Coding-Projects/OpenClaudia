#!/usr/bin/env python3
"""Minimal MCP echo server fixture for integration tests.

Reads newline-delimited JSON-RPC 2.0 requests from stdin and writes
responses to stdout.  Supports the following methods:

  server/discover     -> current DiscoverResult when MCP_CURRENT is set
  initialize          -> canonical legacy InitializeResult
  notifications/initialized -> ignored (no response)
  tools/list          -> hardcoded tool list
  tools/call          -> echoes arguments back as result content
  resources/list      -> returns one resource
  resources/read      -> returns text content

For testing transport-error simulation the server optionally exits
early when it receives a specially-crafted request (method == "die").

Environment variables:
  MCP_NO_TOOLS_CAP    If set, capabilities.tools is omitted from the
                      initialize response, so clients that guard on the
                      capability will skip tools/list.
  MCP_NO_RESOURCES_CAP  Omits capabilities.resources from the response.
  MCP_CURRENT         Implements the MCP 2026-07-28 discovery-era profile.
"""

import json
import os
import sys
import time


def respond(req_id, result):
    msg = json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result})
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def error_response(req_id, code, message, data=None):
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    msg = json.dumps({"jsonrpc": "2.0", "id": req_id, "error": err})
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def current_result(result, cacheable=False):
    result = dict(result)
    result["resultType"] = "complete"
    if cacheable:
        result["ttlMs"] = 0
        result["cacheScope"] = "private"
    return result


def has_current_meta(req):
    meta = req.get("params", {}).get("_meta", {})
    capabilities = meta.get("io.modelcontextprotocol/clientCapabilities", {})
    return (
        meta.get("io.modelcontextprotocol/protocolVersion") == "2026-07-28"
        and isinstance(capabilities, dict)
        and "roots" in capabilities
        and "elicitation" in capabilities
    )


def main():
    no_tools_cap = "MCP_NO_TOOLS_CAP" in os.environ
    no_resources_cap = "MCP_NO_RESOURCES_CAP" in os.environ
    current = "MCP_CURRENT" in os.environ

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue

        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            # Write a parse-error response without an id
            msg = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {exc}"},
                }
            )
            sys.stdout.write(msg + "\n")
            sys.stdout.flush()
            continue

        req_id = req.get("id")
        method = req.get("method", "")

        # Notifications have no id — do not respond
        if req_id is None:
            continue

        if current and not has_current_meta(req):
            error_response(req_id, -32602, "missing current per-request metadata")
            continue

        if method == "server/discover" and current:
            capabilities: dict = {"prompts": {"listChanged": False}, "logging": {}}
            if not no_tools_cap:
                capabilities["tools"] = {"listChanged": False}
            if not no_resources_cap:
                capabilities["resources"] = {}
            respond(
                req_id,
                current_result(
                    {
                        "supportedVersions": ["2026-07-28"],
                        "capabilities": capabilities,
                        "_meta": {
                            "io.modelcontextprotocol/serverInfo": {
                                "name": "echo-server-current",
                                "version": "0.2.0",
                            }
                        },
                    },
                    cacheable=True,
                ),
            )

        elif method == "initialize":
            capabilities: dict = {}
            if not no_tools_cap:
                capabilities["tools"] = {"listChanged": False}
            if not no_resources_cap:
                capabilities["resources"] = {}
            respond(
                req_id,
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": capabilities,
                    "serverInfo": {"name": "echo-server", "version": "0.1.0"},
                },
            )

        elif method == "tools/list":
            result = {
                "tools": [
                    {
                        "name": "echo",
                        "description": "Echo the input back",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"message": {"type": "string"}},
                            "required": ["message"],
                        },
                    },
                    {
                        "name": "fail_tool",
                        "description": "Returns isError:true in result",
                        "inputSchema": {"type": "object", "properties": {}},
                    },
                    {
                        "name": "die_tool",
                        "description": "Closes stdout to simulate a transport disconnect",
                        "inputSchema": {"type": "object", "properties": {}},
                    },
                    {
                        "name": "slow_tool",
                        "description": "Sleeps before returning",
                        "inputSchema": {"type": "object", "properties": {}},
                    },
                ]
            }
            respond(
                req_id,
                current_result(result, cacheable=True) if current else result,
            )

        elif method == "tools/call":
            params = req.get("params", {})
            tool_name = params.get("name", "")
            args = params.get("arguments", {})

            if tool_name == "fail_tool":
                # Return a tool-level error payload (isError=true).
                # OC must surface this as a ToolReportedError, not as a
                # successful raw Value.
                result = {
                    "isError": True,
                    "content": [
                        {"type": "text", "text": "tool-level error occurred"}
                    ],
                }
                respond(
                    req_id,
                    current_result(result) if current else result,
                )
            elif tool_name == "die_tool":
                # Simulate transport disconnect during tools/call.
                sys.stdout.close()
                sys.exit(0)
            elif tool_name == "slow_tool":
                time.sleep(2)
                result = {
                    "isError": False,
                    "content": [{"type": "text", "text": "slow result"}],
                }
                respond(
                    req_id,
                    current_result(result) if current else result,
                )
            else:
                result = {
                    "isError": False,
                    "content": [
                        {"type": "text", "text": json.dumps(args)}
                    ],
                    "structuredContent": args,
                }
                respond(
                    req_id,
                    current_result(result) if current else result,
                )

        elif method == "resources/list":
            result = {
                "resources": [
                    {
                        "uri": "echo://hello",
                        "name": "hello",
                        "mimeType": "text/plain",
                    }
                ]
            }
            respond(
                req_id,
                current_result(result, cacheable=True) if current else result,
            )

        elif method == "resources/read":
            contents = [
                {
                    "uri": "echo://hello",
                    "text": "hello world",
                    "mimeType": "text/plain",
                }
            ]
            if current:
                contents.append(
                    {
                        "uri": "echo://pixel",
                        "blob": "aGVsbG8=",
                        "mimeType": "image/png",
                    }
                )
            result = {
                "contents": contents
            }
            respond(
                req_id,
                current_result(result, cacheable=True) if current else result,
            )

        elif method == "prompts/list" and current:
            respond(
                req_id,
                current_result(
                    {
                        "prompts": [
                            {
                                "name": "echo_prompt",
                                "arguments": [{"name": "message", "required": True}],
                            }
                        ]
                    },
                    cacheable=True,
                ),
            )

        elif method == "prompts/get" and current:
            message = req.get("params", {}).get("arguments", {}).get("message", "")
            respond(
                req_id,
                current_result(
                    {
                        "messages": [
                            {"role": "user", "content": {"type": "text", "text": message}}
                        ]
                    }
                ),
            )

        elif method == "rpc_error_with_data":
            # Synthetic method to test error-code surfacing (B5).
            # Returns a JSON-RPC error that includes a structured `data` field.
            error_response(
                req_id,
                -32099,
                "custom server error",
                {"detail": "extra context"},
            )

        elif method == "die":
            # Simulate transport disconnect mid-call (B6).
            # Close stdout without writing a response; the client's read_line
            # will see EOF and return a Transport error.
            sys.stdout.close()
            sys.exit(0)

        else:
            error_response(req_id, -32601, f"Method not found: {method}")


if __name__ == "__main__":
    main()
