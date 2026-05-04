"""
Devin API client wrapper.
"""

import logging
import os
from typing import Any

import httpx

log = logging.getLogger(__name__)

DEVIN_API_KEY = os.environ.get("DEVIN_API_KEY", "")
DEVIN_ORG_ID = os.environ.get("DEVIN_ORG_ID", "")
DEVIN_BASE_URL = "https://api.devin.ai/v3"


class DevinClient:
    def __init__(self) -> None:
        if not DEVIN_API_KEY:
            log.warning("DEVIN_API_KEY not set")
        if not DEVIN_ORG_ID:
            log.warning("DEVIN_ORG_ID not set")

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {DEVIN_API_KEY}",
            "Content-Type": "application/json",
        }

    async def create_session(
        self,
        prompt: str,
        title: str | None = None,
        tags: list[str] | None = None,
        repos: list[str] | None = None,
    ) -> dict[str, Any]:
        url = f"{DEVIN_BASE_URL}/organizations/{DEVIN_ORG_ID}/sessions"
        body: dict[str, Any] = {"prompt": prompt}
        if title:
            body["title"] = title
        if tags:
            body["tags"] = tags
        if repos:
            body["repos"] = repos

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(url, json=body, headers=self._headers)
            resp.raise_for_status()
            data = resp.json()
            log.info("Created Devin session %s", data.get("session_id"))
            return data

    async def get_session(
        self,
        session_id: str,
        client: httpx.AsyncClient | None = None,
    ) -> dict[str, Any]:
        url = f"{DEVIN_BASE_URL}/organizations/{DEVIN_ORG_ID}/sessions/{session_id}"

        async def _fetch(c: httpx.AsyncClient) -> dict[str, Any]:
            resp = await c.get(url, headers=self._headers)
            resp.raise_for_status()
            return resp.json()

        if client:
            return await _fetch(client)
        async with httpx.AsyncClient(timeout=30) as c:
            return await _fetch(c)

    async def list_sessions(
        self,
        tags: list[str] | None = None,
        first: int = 50,
    ) -> list[dict[str, Any]]:
        url = f"{DEVIN_BASE_URL}/organizations/{DEVIN_ORG_ID}/sessions"
        params: dict[str, Any] = {"first": first}
        if tags:
            params["tags"] = tags

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, headers=self._headers, params=params)
            resp.raise_for_status()
            return resp.json().get("items", [])
