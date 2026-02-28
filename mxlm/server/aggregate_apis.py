import argparse
import json

import requests
from flask import Flask, Response, has_request_context, jsonify, redirect, request


ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
UPSTREAM_TIMEOUT = (10, 4 * 60 * 60)
JSON_TRUNCATE_LIMIT = 4000
JSON_TRUNCATE_KEEP = 1000
JSON_TRUNCATE_PLACEHOLDER = "\n... ({reason}) ...\n"


def slim_json_strings(
    data,
    *,
    limit=JSON_TRUNCATE_LIMIT,
    keep=JSON_TRUNCATE_KEEP,
    placeholder=JSON_TRUNCATE_PLACEHOLDER,
):
    """Recursively trim strings that exceed ``limit`` characters."""
    if isinstance(data, dict):
        return {
            key: slim_json_strings(
                value, limit=limit, keep=keep, placeholder=placeholder
            )
            for key, value in data.items()
        }
    if isinstance(data, list):
        return [
            slim_json_strings(value, limit=limit, keep=keep, placeholder=placeholder)
            for value in data
        ]
    if isinstance(data, str):
        if len(data) <= limit:
            return data
        head = data[:keep]
        tail = data[-keep:]
        reason = f"omitted {len(data) - 2 * keep} chars"
        return head + placeholder.format(reason=reason) + tail
    return data


def split_csv_arg(value):
    if value is None:
        return None
    s = value.strip()
    if not s:
        return []
    return [x.strip() for x in s.split(",") if x.strip()]


def normalize_upstreams(base_urls, api_keys):
    base_urls = split_csv_arg(base_urls) or []
    if not base_urls:
        raise ValueError("base_urls is required")

    keys = split_csv_arg(api_keys)
    if keys is None or len(keys) == 0:
        api_keys = [None] * len(base_urls)
    elif len(keys) == len(base_urls):
        api_keys = keys
    else:
        raise ValueError("api_keys must be empty or same length as base_urls")

    return base_urls, api_keys


def build_upstream_url(base_url, subpath):
    base = base_url.rstrip("/")
    if subpath:
        return f"{base}/{subpath.lstrip('/')}"
    return base


def build_upstream_headers(api_key):
    headers = {}
    if has_request_context():
        for k, v in request.headers.items():
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


def parse_body_json():
    try:
        return json.loads(request.get_data(as_text=True) or "{}")
    except Exception:
        return {}


def create_app(base_urls, api_keys, new_api_key=None, debug=False):
    app = Flask(__name__)
    model_to_upstream_idx = {}
    response_to_upstream_idx = {}
    response_to_model = {}

    def pretty_json(value):
        return json.dumps(
            slim_json_strings(value), ensure_ascii=False, indent=2, default=str
        )

    def debug_print(title, value=None):
        if not debug:
            return
        if value is None:
            print(title, flush=True)
        else:
            if isinstance(value, str):
                formatted = value
            else:
                formatted = pretty_json(value)
            print(f"{title}: {formatted}", flush=True)

    def debug_dump_response_body(content_bytes):
        if not debug:
            return
        text = content_bytes.decode("utf-8", errors="replace")
        try:
            pretty = json.loads(text)
        except Exception:
            pretty = slim_json_strings(text)
        debug_print("[aggregate_apis][debug] response body", pretty)

    def debug_dump_stream_chunk(content_bytes):
        if not debug:
            return
        text = content_bytes.decode("utf-8", errors="replace")
        debug_print(
            "[aggregate_apis][debug] response stream chunk", slim_json_strings(text)
        )

    def extract_response_id(subpath):
        if not subpath.startswith("responses/"):
            return ""
        parts = subpath.split("/")
        if len(parts) < 2:
            return ""
        return parts[1]

    def cache_response_upstream(
        subpath, method, stream_flag, selected_idx, content_bytes
    ):
        if method != "POST" or subpath != "responses" or stream_flag:
            return
        try:
            payload = json.loads(content_bytes.decode("utf-8"))
        except Exception:
            return
        response_id = payload.get("id") if isinstance(payload, dict) else None
        if isinstance(response_id, str) and response_id:
            response_to_upstream_idx[response_id] = selected_idx
            debug_print("[aggregate_apis][debug] cached response id", response_id)
            response_model = payload.get("model") if isinstance(payload, dict) else None
            if isinstance(response_model, str) and response_model:
                response_to_model[response_id] = response_model
                debug_print(
                    "[aggregate_apis][debug] cached response model", response_model
                )

    @app.route("/", methods=["GET"])
    def root_redirect():
        return redirect("/v1/models", code=302)

    @app.route("/v1", methods=["GET"])
    def v1_redirect():
        return redirect("/v1/models", code=302)

    def refresh_model_map(strict=False):
        nonlocal model_to_upstream_idx
        new_map = {}
        for idx, bu in enumerate(base_urls):
            url = build_upstream_url(bu, "models")
            try:
                headers = build_upstream_headers(api_keys[idx])
                r = requests.get(url, headers=headers, timeout=UPSTREAM_TIMEOUT)
                r.raise_for_status()
                d = r.json()
                items = d.get("data", []) if isinstance(d, dict) else []
                for it in items:
                    model_id = it.get("id") if isinstance(it, dict) else None
                    if model_id and model_id not in new_map:
                        new_map[model_id] = idx
            except Exception as e:
                debug_print(
                    "[aggregate_apis][debug] refresh model map failed",
                    f"upstream[{idx}] {url}: {e}",
                )
                if strict:
                    raise RuntimeError(
                        f"initial /models fetch failed: upstream[{idx}] {url}: {e}"
                    ) from e
                continue
        model_to_upstream_idx = new_map
        debug_print(
            "[aggregate_apis][debug] refreshed model map size",
            len(model_to_upstream_idx),
        )

    refresh_model_map(strict=True)

    @app.before_request
    def auth_and_preflight():
        if request.method == "OPTIONS":
            return Response(status=204)
        if new_api_key:
            auth = request.headers.get("Authorization", "")
            expect = f"Bearer {new_api_key}"
            if auth != expect:
                return (
                    jsonify(
                        {"error": {"message": "unauthorized", "type": "auth_error"}}
                    ),
                    401,
                )

    @app.after_request
    def add_cors(resp):
        req_headers = request.headers.get("Access-Control-Request-Headers", "*")
        req_method = request.headers.get("Access-Control-Request-Method", "*")
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = req_headers
        resp.headers["Access-Control-Allow-Methods"] = req_method
        resp.headers["Access-Control-Max-Age"] = "86400"
        debug_print("[aggregate_apis][debug] response status", resp.status_code)
        debug_print("[aggregate_apis][debug] response headers", dict(resp.headers))
        if debug:
            print(f"{'='*60}\n", flush=True)
        return resp

    @app.route("/v1/", defaults={"subpath": ""}, methods=ALL_METHODS)
    @app.route("/v1/<path:subpath>", methods=ALL_METHODS)
    def proxy(subpath):
        if request.method == "GET" and subpath == "":
            return redirect("/v1/models", code=302)

        request_query = request.query_string.decode("utf-8")
        request_headers = dict(request.headers)
        request_body = request.get_data()
        if debug:
            print(f"\n{'='*60}", flush=True)
            debug_print("[aggregate_apis][debug] request method", request.method)
            debug_print("[aggregate_apis][debug] request path", f"/v1/{subpath}")
            debug_print("[aggregate_apis][debug] request query", request_query or "-")
            debug_print("[aggregate_apis][debug] request headers", request_headers)

        if subpath == "models" and request.method in {"GET", "POST"}:
            refresh_model_map()
            merged = []
            for idx, bu in enumerate(base_urls):
                headers = build_upstream_headers(api_keys[idx])
                url = build_upstream_url(bu, "models")
                try:
                    r = requests.get(url, headers=headers, timeout=UPSTREAM_TIMEOUT)
                    d = r.json()
                    items = d.get("data", []) if isinstance(d, dict) else []
                    for it in items:
                        if isinstance(it, dict):
                            item = dict(it)
                            item["aggregate_api_key"] = (
                                f"base_url{idx}:{item.get('id', '')}"
                            )
                            item["aggregate_upstream_index"] = idx
                            item["aggregate_upstream_base_url"] = bu
                            merged.append(item)
                        else:
                            merged.append(it)
                except Exception:
                    continue
            debug_print("[aggregate_apis][debug] merged models count", len(merged))
            return jsonify({"object": "list", "data": merged})

        body = parse_body_json()
        stream_flag = bool(body.get("stream")) if isinstance(body, dict) else False
        if request_body:
            if body:
                debug_print("[aggregate_apis][debug] request body", body)
            else:
                debug_print(
                    "[aggregate_apis][debug] request body",
                    request_body.decode("utf-8", errors="replace"),
                )
        req_model = body.get("model", "") if isinstance(body, dict) else ""
        req_response_id = extract_response_id(subpath)
        selected_idx = 0
        route_reason = "fallback to upstream[0]"
        if (
            isinstance(req_model, str)
            and req_model.startswith("base_url")
            and ":" in req_model
        ):
            prefix, _rest = req_model.split(":", 1)
            idx_str = prefix[len("base_url") :]
            if idx_str.isdigit():
                idx = int(idx_str)
                if 0 <= idx < len(base_urls):
                    selected_idx = idx
                    route_reason = "aggregate_api_key prefix"
        elif req_model in model_to_upstream_idx:
            selected_idx = model_to_upstream_idx[req_model]
            route_reason = "exact model id mapping"
        elif req_response_id in response_to_upstream_idx:
            selected_idx = response_to_upstream_idx[req_response_id]
            route_reason = "response id mapping"

        bu = base_urls[selected_idx]
        ak = api_keys[selected_idx]
        url = build_upstream_url(bu, subpath)
        if request_query:
            url = f"{url}?{request_query}"
        debug_print("[aggregate_apis][debug] request model", req_model or "-")
        debug_print(
            "[aggregate_apis][debug] request response id", req_response_id or "-"
        )
        debug_print("[aggregate_apis][debug] route reason", route_reason)
        debug_print("[aggregate_apis][debug] selected upstream index", selected_idx)
        debug_print("[aggregate_apis][debug] target url", url)

        headers = build_upstream_headers(ak)
        cached_response_model = response_to_model.get(req_response_id)
        if cached_response_model and not headers.get("X-Model"):
            headers["X-Model"] = cached_response_model
        upstream = requests.request(
            method=request.method,
            url=url,
            headers=headers,
            data=request_body,
            allow_redirects=False,
            timeout=UPSTREAM_TIMEOUT,
            stream=True,
        )
        if debug:
            debug_print("[aggregate_apis][debug] upstream status", upstream.status_code)
            debug_print(
                "[aggregate_apis][debug] upstream headers",
                dict(upstream.headers.items()),
            )

        upstream_content_type = upstream.headers.get("Content-Type", "").lower()
        is_sse_stream = "text/event-stream" in upstream_content_type
        resp_headers = normalize_response_headers(upstream.headers)
        if not stream_flag and subpath == "responses" and request.method == "POST":
            response_body = upstream.content
            cache_response_upstream(
                subpath, request.method, stream_flag, selected_idx, response_body
            )
            if debug:
                debug_dump_response_body(response_body)
            return Response(
                response_body, status=upstream.status_code, headers=resp_headers
            )

        if debug and not stream_flag:
            response_body = upstream.content
            debug_dump_response_body(response_body)
            return Response(
                response_body, status=upstream.status_code, headers=resp_headers
            )

        def gen():
            for chunk in upstream.iter_content(chunk_size=8192):
                if chunk:
                    if debug and is_sse_stream:
                        debug_dump_stream_chunk(chunk)
                    yield chunk

        return Response(gen(), status=upstream.status_code, headers=resp_headers)

    return app


def main():
    parser = argparse.ArgumentParser(
        description="Aggregate multiple OpenAI-compatible upstream APIs into one /v1 endpoint.",
        epilog=(
            "Model routing priority:\n"
            "  1) aggregate_api_key like base_url1:model_name\n"
            "  2) exact model id from /v1/models mapping\n"
            "  3) fallback to upstream[0]\n"
            "Duplicate model ids in mapping: first upstream in --base_urls wins."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        allow_abbrev=False,
    )
    parser.add_argument("--base_urls", required=True, help="Comma-separated base URLs")
    parser.add_argument(
        "--api_keys", default="", help="Optional comma-separated API keys"
    )
    parser.add_argument(
        "--new_api_key", default="", help="Optional key for this aggregate API"
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9400)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    base_urls, api_keys = normalize_upstreams(args.base_urls, args.api_keys)
    app = create_app(
        base_urls,
        api_keys,
        new_api_key=args.new_api_key or None,
        debug=args.debug,
    )

    print(f"[aggregate_apis] listening on http://{args.host}:{args.port}")
    print("[aggregate_apis] routes:")
    print("  - /v1/models (aggregate + refresh model routing map)")
    print("  - /v1/* (route by model, fallback to upstream[0])")
    print("[aggregate_apis] model routing priority:")
    print("  1) aggregate_api_key like base_url1:model_name")
    print("  2) exact model id from /models mapping")
    print("  3) fallback to upstream[0]")

    app.run(
        host=args.host,
        port=args.port,
        threaded=True,
        debug=args.debug,
        use_reloader=args.debug,
    )


if __name__ == "__main__":
    main()
