"""
AgentGuard - AI API Proxy Handler
Routes AI calls through AgentGuard for monitoring before forwarding to providers.
Usage: Set your AI API base URL to http://localhost:8000/proxy/openai/v1
"""
import httpx
import os
import logging
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import StreamingResponse

router = APIRouter()
logger = logging.getLogger("agentguard.proxy")

PROVIDER_URLS = {
    "openai": "https://api.openai.com",
    "anthropic": "https://api.anthropic.com",
}


@router.api_route("/openai/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_openai(path: str, request: Request):
    """Transparent proxy for OpenAI API calls."""
    return await _proxy_request("openai", path, request)


@router.api_route("/anthropic/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])  
async def proxy_anthropic(path: str, request: Request):
    """Transparent proxy for Anthropic API calls."""
    return await _proxy_request("anthropic", path, request)


async def _proxy_request(provider: str, path: str, request: Request):
    """Forward request to AI provider, interceptor middleware handles logging."""
    base_url = PROVIDER_URLS.get(provider)
    if not base_url:
        raise HTTPException(400, f"Unknown provider: {provider}")
    
    # Get provider API key from environment
    key_map = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}
    api_key = os.environ.get(key_map[provider])
    if not api_key:
        raise HTTPException(500, f"Provider API key not configured: {key_map[provider]}")
    
    # Build forward URL
    target_url = f"{base_url}/{path}"
    if request.url.query:
        target_url += f"?{request.url.query}"
    
    # Forward headers (replace auth with provider key)
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("content-length", None)
    
    if provider == "openai":
        headers["Authorization"] = f"Bearer {api_key}"
    elif provider == "anthropic":
        headers["x-api-key"] = api_key
        headers["anthropic-version"] = "2023-06-01"
    
    body = await request.body()
    
    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
        )
    
    return StreamingResponse(
        iter([response.content]),
        status_code=response.status_code,
        headers=dict(response.headers),
        media_type=response.headers.get("content-type")
    )
