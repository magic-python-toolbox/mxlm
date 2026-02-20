import copy
import json
import queue
import threading
import time
import traceback
import urllib.parse


ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]


def decode_url_config_path(path_str, separator=",", assignor="@"):
    result = {}
    if not path_str:
        return result

    pairs = path_str.split(separator)
    for pair in pairs:
        if assignor not in pair:
            continue
        full_key, encoded_val = pair.split(assignor, 1)
        val_str = urllib.parse.unquote(encoded_val)
        try:
            if "." in val_str:
                value = float(val_str)
            else:
                value = int(val_str)
        except ValueError:
            value = val_str
            low = value.lower()
            if low == "true":
                value = True
            elif low == "false":
                value = False

        keys = full_key.split(".")
        cur = result
        for k in keys[:-1]:
            if k not in cur or not isinstance(cur[k], dict):
                cur[k] = {}
            cur = cur[k]
        cur[keys[-1]] = value

    return result


def build_upstream_url(base_url, subpath):
    base = base_url.rstrip("/")
    if subpath:
        return f"{base}/{subpath.lstrip('/')}"
    return base


def build_upstream_headers(api_key, req_headers):
    headers = {}
    for k, v in req_headers.items():
        lk = k.lower()
        if lk in {"host", "content-length", "connection"}:
            continue
        headers[k] = v
    if api_key and api_key != "no-key":
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def normalize_response_headers(headers):
    blocked = {"content-length", "transfer-encoding", "content-encoding", "connection"}
    out = {}
    for k, v in headers.items():
        if k.lower() in blocked:
            continue
        out[k] = v
    return out


def build_chat_completion_response(message, extra_info=None, stream=False):
    now = int(time.time())
    rid = f"chatcmpl-mxlm.hijack_chat_api-{now}"
    msg = copy.deepcopy(message) if message else {"role": "assistant", "content": ""}
    if "role" not in msg:
        msg["role"] = "assistant"

    if stream:
        chunk = {
            "id": rid,
            "object": "chat.completion.chunk",
            "created": now,
            "model": "",
            "choices": [{"index": 0, "delta": msg, "finish_reason": "stop"}],
        }
        if isinstance(extra_info, dict):
            chunk.update(copy.deepcopy(extra_info))
        return chunk

    resp = {
        "id": rid,
        "object": "chat.completion",
        "created": now,
        "model": "",
        "choices": [{"index": 0, "message": msg, "finish_reason": "stop"}],
    }
    if isinstance(extra_info, dict):
        resp.update(copy.deepcopy(extra_info))
    return resp


def _parse_request_json(request_body):
    try:
        return json.loads(request_body.decode("utf-8") or "{}")
    except Exception:
        return {}


def hijack_chat_api(
    app,
    hijack_path,
    process_func,
    base_url,
    api_key=None,
    heartbeat_interval_seconds=600,
    upstream_timeout=(10, 4 * 60 * 60),
    enable_cors=True,
):
    """
    Register a reusable hijack endpoint for chat/completions.

    Routes:
    - /{hijack_path}/v1/*
    - /{hijack_path}/{url_config}/v1/*

    process_func(body, headers, url_config) should return:
    - direct_forward: bool
    - message: dict (OpenAI-style assistant message)
    - extra_info: dict (deep-copied into response root)
    - content: str (optional shortcut if message is omitted)
    """
    import requests
    from flask import Response, jsonify, request, stream_with_context

    path_prefix = hijack_path.strip("/")

    if enable_cors and not app.config.get("_MXLH_CORS_INSTALLED"):
        app.config["_MXLH_CORS_INSTALLED"] = True

        @app.before_request
        def _mxlh_handle_preflight():
            if request.method == "OPTIONS":
                return Response(status=204)

        @app.after_request
        def _mxlh_add_cors_headers(resp):
            req_headers = request.headers.get("Access-Control-Request-Headers", "*")
            req_method = request.headers.get("Access-Control-Request-Method", "*")
            resp.headers["Access-Control-Allow-Origin"] = "*"
            resp.headers["Access-Control-Allow-Headers"] = req_headers
            resp.headers["Access-Control-Allow-Methods"] = req_method
            resp.headers["Access-Control-Max-Age"] = "86400"
            return resp

    def proxy_plain(subpath, req_headers, req_method, req_body, req_query):
        url = build_upstream_url(base_url, subpath)
        headers = build_upstream_headers(api_key, req_headers)
        if req_query:
            url = f"{url}?{req_query}"

        upstream = requests.request(
            method=req_method,
            url=url,
            headers=headers,
            data=req_body,
            allow_redirects=False,
            timeout=upstream_timeout,
            stream=False,
        )
        resp_headers = normalize_response_headers(upstream.headers)
        return Response(
            upstream.content, status=upstream.status_code, headers=resp_headers
        )

    def handle_hijack(subpath, url_config):
        request_method = request.method
        request_body = request.get_data()
        request_query = request.query_string.decode("utf-8")
        req_headers = dict(request.headers.items())

        if subpath != "chat/completions":
            return proxy_plain(
                subpath, req_headers, request_method, request_body, request_query
            )

        body = _parse_request_json(request_body)
        stream_flag = bool(body.get("stream"))
        result_q = queue.Queue()

        def worker():
            try:
                if stream_flag:
                    result_q.put(
                        (
                            "meta",
                            (
                                200,
                                {
                                    "Content-Type": "text/event-stream; charset=utf-8",
                                },
                            ),
                        )
                    )

                process_ret = process_func(body, req_headers, url_config) or {}

                if process_ret.get("direct_forward"):
                    url = build_upstream_url(base_url, subpath)
                    headers = build_upstream_headers(api_key, req_headers)
                    if request_query:
                        url = f"{url}?{request_query}"
                    with requests.request(
                        method=request_method,
                        url=url,
                        headers=headers,
                        data=request_body,
                        allow_redirects=False,
                        timeout=upstream_timeout,
                        stream=True,
                    ) as upstream:
                        if not stream_flag:
                            result_q.put(
                                (
                                    "meta",
                                    (
                                        upstream.status_code,
                                        normalize_response_headers(upstream.headers),
                                    ),
                                )
                            )
                        for chunk in upstream.iter_content(chunk_size=8192):
                            if chunk:
                                result_q.put(("chunk", chunk))
                    result_q.put(("done", None))
                    return

                if not stream_flag:
                    result_q.put(
                        (
                            "meta",
                            (
                                200,
                                {
                                    "Content-Type": "application/json",
                                },
                            ),
                        )
                    )

                message = process_ret.get("message")
                if not message and "content" in process_ret:
                    message = {
                        "role": "assistant",
                        "content": process_ret.get("content", ""),
                    }
                extra_info = process_ret.get("extra_info")

                if stream_flag:
                    result_q.put(("chunk", b": hijack-stream-start\n\n"))
                    chunk_obj = build_chat_completion_response(
                        message, extra_info=extra_info, stream=True
                    )
                    result_q.put(
                        (
                            "chunk",
                            f"data: {json.dumps(chunk_obj, ensure_ascii=False)}\n\n".encode(
                                "utf-8"
                            ),
                        )
                    )
                    result_q.put(("chunk", b"data: [DONE]\n\n"))
                else:
                    resp_obj = build_chat_completion_response(
                        message, extra_info=extra_info, stream=False
                    )
                    result_q.put(
                        (
                            "chunk",
                            json.dumps(resp_obj, ensure_ascii=False).encode("utf-8"),
                        )
                    )
                result_q.put(("done", None))
            except Exception as e:
                print(
                    "[hijack_chat_api] traceback:\n" + traceback.format_exc(),
                    flush=True,
                )
                payload = {"error": {"message": str(e), "type": "proxy_error"}}
                result_q.put(("error", payload))
                result_q.put(("done", None))

        threading.Thread(target=worker, daemon=True).start()

        first_kind = None
        first_payload = None
        while first_kind != "meta":
            first_kind, first_payload = result_q.get()
            if first_kind == "error":
                return jsonify(first_payload), 502
            if first_kind == "done":
                return (
                    jsonify(
                        {
                            "error": {
                                "message": "hijack finished before response meta",
                                "type": "proxy_error",
                            }
                        }
                    ),
                    502,
                )

        status_code, resp_headers = first_payload
        if stream_flag and status_code == 200:
            resp_headers["Cache-Control"] = "no-cache, no-transform"
            resp_headers["X-Accel-Buffering"] = "no"
            resp_headers["Connection"] = "keep-alive"

        @stream_with_context
        def generate():
            heartbeat = b": ping\n\n" if stream_flag else b" \n"
            if stream_flag and status_code == 200:
                yield b": stream-open\n\n"
            while True:
                try:
                    kind, payload = result_q.get(timeout=heartbeat_interval_seconds)
                    if kind == "chunk":
                        yield payload
                    elif kind == "error":
                        if stream_flag:
                            yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode(
                                "utf-8"
                            )
                        else:
                            yield json.dumps(payload, ensure_ascii=False).encode(
                                "utf-8"
                            )
                    elif kind == "done":
                        break
                except queue.Empty:
                    yield heartbeat

        return Response(generate(), status=status_code, headers=resp_headers)

    @app.route(f"/{path_prefix}/v1", defaults={"subpath": ""}, methods=ALL_METHODS)
    @app.route(f"/{path_prefix}/v1/", defaults={"subpath": ""}, methods=ALL_METHODS)
    @app.route(f"/{path_prefix}/v1/<path:subpath>", methods=ALL_METHODS)
    def _hijack_empty_url_config(subpath):
        return handle_hijack(subpath, {})

    @app.route(f"/{path_prefix}/<path:url_config_and_v1>", methods=ALL_METHODS)
    def _hijack_with_url_config(url_config_and_v1):
        marker = "/v1/"
        if marker in url_config_and_v1:
            url_config_path, subpath = url_config_and_v1.split(marker, 1)
        elif url_config_and_v1.endswith("/v1"):
            url_config_path = url_config_and_v1[: -len("/v1")]
            subpath = ""
        else:
            return jsonify({"error": "path must include /v1/"}), 400

        url_config = decode_url_config_path(url_config_path)
        return handle_hijack(subpath, url_config)
