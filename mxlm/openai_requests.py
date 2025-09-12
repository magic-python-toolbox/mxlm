"""
openai_sync_client.py
=====================
A minimal *synchronous* replacement for the official `openai` Python package,
covering the most common endpoints – currently `chat.completions.create` and
`models.list` – using the `requests` HTTP library.

Example
-------
```python
from openai_sync_client import OpenAI

client = OpenAI(api_key="sk-...your api key...")

# One‑off completion
response = client.chat.completions.create({
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Hello!"}]
})
print(response)

# Streaming completion
for chunk in client.chat.completions.create({
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Stream me!"}],
    "stream": True
}):
    print(chunk)

# List available models
print(client.models.list())
```
"""

from __future__ import annotations

import json
from typing import Any, Dict, Generator, Iterable, Union, Mapping

import requests

__version__ = "1.1.1"
__all__ = ["OpenAI"]
DEFAULT_MAX_RETRIES = 2
DEFAULT_TIMEOUT = 600  # seconds
DEFAULT_CONNECTION_LIMITS = {
    "max_connections": 1000,
    "max_keepalive_connections": 100,
}


class LikeDict(dict):
    def dict(self):
        return self


class OpenAI:
    """A drop‑in, synchronous substitute for the `openai` Python SDK.

    Parameters
    ----------
    api_key : str
        Your OpenAI API key (e.g. ``"sk‑..."``).
    base_url : str, optional
        Alternate base URL for compatible endpoints. Defaults to
        ``"https://api.openai.com/v1"``.
    session : requests.Session | None, optional
        Re‑use an existing :class:`requests.Session` (recommended for high
        throughput). If *None*, an ephemeral session is created per request.
    """

    # ---------------------------------------------------------------------
    # Construction helpers
    # ---------------------------------------------------------------------

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str = "https://api.openai.com/v1",
        session: requests.Session | None = None,
        organization: str | None = None,
        project: str | None = None,
        webhook_secret: str | None = None,
        websocket_base_url: str | None = None,
        timeout=None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        default_headers: Mapping[str, str] | None = None,
        default_query: Mapping[str, object] | None = None,
        http_client=None,
        _strict_response_validation: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._session = session  # may be None – handled lazily

        self._headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        # Public sub‑namespaces ------------------------------------------------
        self.chat = self._ChatNamespace(self)
        self.models = self._ModelsNamespace(self)

    # ------------------------------------------------------------------
    # Namespaces mirroring official SDK layout
    # ------------------------------------------------------------------

    class _ChatNamespace:
        def __init__(self, outer: "OpenAI") -> None:
            self._outer = outer
            self.completions = self._CompletionsNamespace(outer)

        class _CompletionsNamespace:
            def __init__(self, outer: "OpenAI") -> None:
                self._outer = outer

            def create(
                self,
                messages,
                temperature=1,
                top_p=1,
                max_tokens=1024,
                stream=False,
                **request_kwargs: Any,
            ) -> Union[Dict[str, Any], Generator[Dict[str, Any], None, None]]:
                return self._outer._create_chat_completion(
                    messages,
                    temperature=temperature,
                    top_p=top_p,
                    max_tokens=max_tokens,
                    stream=stream,
                    **request_kwargs,
                )

    class _ModelsNamespace:
        def __init__(self, outer: "OpenAI") -> None:
            self._outer = outer

        def list(self, **request_kwargs: Any) -> Iterable[Dict[str, Any]]:
            """GET ``/models`` and return the ``data`` array."""
            return self._outer._list_models(**request_kwargs)

    # ------------------------------------------------------------------
    # Internal helpers – implementation details
    # ------------------------------------------------------------------

    def _post(
        self,
        path: str,
        *,
        json_body: Dict[str, Any],
        **request_kwargs: Any,
    ) -> requests.Response:
        url = f"{self.base_url}{path}"
        sess = self._session or requests
        if "extra_body" in json_body:
            json_body.update(json_body.pop("extra_body"))
        # from boxx import tree
        # tree(json_body)
        return sess.post(
            url,
            headers=self._headers,
            json=json_body,
            timeout=request_kwargs.pop("timeout", 600),  # sensible default
            **request_kwargs,
        )

    # ------------------------------------------------------------------
    # Publicly exposed low‑level methods (mirrored by namespaces above)
    # ------------------------------------------------------------------

    def _create_chat_completion(
        self, messages, **request_kwargs: Any
    ) -> Union[Dict[str, Any], Generator[Dict[str, Any], None, None]]:
        stream = bool(request_kwargs.get("stream"))
        request_kwargs["messages"] = messages
        response = self._post("/chat/completions", json_body=request_kwargs)

        if not response.ok:
            raise RuntimeError(
                f"Failed to fetch completions: {response.status_code} – {response.text}"
            )

        if not stream:
            return LikeDict(response.json())

        # Streaming SSE – yield parsed events lazily -----------------------
        class StreamResponse:
            def __init__(self, response, event_stream):
                self.response = response
                self._event_stream = event_stream

            def __iter__(self):
                return self

            def __next__(self):
                return next(self._event_stream)

        def _event_stream() -> Generator[Dict[str, Any], None, None]:
            for line in response.iter_lines(decode_unicode=True):
                if not line:  # keep‑alive / event delimiter
                    continue
                if not line.startswith("data: "):
                    continue  # ignore comments or other fields
                data = line[6:].strip()
                if data == "[DONE]":
                    break
                parsed_data = json.loads(data)
                # Only yield chunks that have choices with valid content
                # print(data, '\n'*2)
                yield LikeDict(parsed_data)

        return StreamResponse(response, _event_stream())

    def _list_models(self, **request_kwargs: Any) -> Iterable[Dict[str, Any]]:
        url = f"{self.base_url}/models"
        sess = self._session or requests
        response = sess.get(
            url,
            headers=self._headers,
            timeout=request_kwargs.pop("timeout", 60),
            **request_kwargs,
        )
        if not response.ok:
            raise RuntimeError(
                f"Failed to fetch models: {response.status_code} – {response.text}"
            )
        payload = response.json()
        return LikeDict(payload)
