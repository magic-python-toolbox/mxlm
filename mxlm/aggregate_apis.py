import argparse
import json

import requests
from flask import Flask, Response, jsonify, request


ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
UPSTREAM_TIMEOUT = (10, 4 * 60 * 60)


def split_csv_arg(value):
    if value is None:
        return None
    s = value.strip()
    if not s:
        return []
    return [x.strip() for x in s.split(",") if x.strip()]


def normalize_upstreams(base_url, api_key):
    base_urls = split_csv_arg(base_url) or []
    if not base_urls:
        raise ValueError("base_url is required")

    keys = split_csv_arg(api_key)
    if keys is None or len(keys) == 0:
        api_keys = [None] * len(base_urls)
    elif len(keys) == len(base_urls):
        api_keys = keys
    else:
        raise ValueError("api_key must be None or same length as base_url")

    return base_urls, api_keys


def build_upstream_url(base_url, subpath):
    base = base_url.rstrip("/")
    if subpath:
        return f"{base}/{subpath.lstrip('/')}"
    return base


def build_upstream_headers(api_key):
    headers = {}
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


def create_app(base_urls, api_keys, new_api_key=None):
    app = Flask(__name__)
    model_to_upstream_idx = {}

    def refresh_model_map():
        nonlocal model_to_upstream_idx
        new_map = {}
        for idx, bu in enumerate(base_urls):
            try:
                url = build_upstream_url(bu, "models")
                headers = build_upstream_headers(api_keys[idx])
                r = requests.get(url, headers=headers, timeout=UPSTREAM_TIMEOUT)
                d = r.json()
                items = d.get("data", []) if isinstance(d, dict) else []
                for it in items:
                    model_id = it.get("id") if isinstance(it, dict) else None
                    if model_id and model_id not in new_map:
                        new_map[model_id] = idx
            except Exception:
                continue
        model_to_upstream_idx = new_map

    refresh_model_map()

    @app.before_request
    def auth_and_preflight():
        if request.method == "OPTIONS":
            return Response(status=204)
        if new_api_key:
            auth = request.headers.get("Authorization", "")
            expect = f"Bearer {new_api_key}"
            if auth != expect:
                return jsonify({"error": {"message": "unauthorized", "type": "auth_error"}}), 401

    @app.after_request
    def add_cors(resp):
        req_headers = request.headers.get("Access-Control-Request-Headers", "*")
        req_method = request.headers.get("Access-Control-Request-Method", "*")
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = req_headers
        resp.headers["Access-Control-Allow-Methods"] = req_method
        resp.headers["Access-Control-Max-Age"] = "86400"
        return resp

    @app.route("/v1/", defaults={"subpath": ""}, methods=ALL_METHODS)
    @app.route("/v1/<path:subpath>", methods=ALL_METHODS)
    def proxy(subpath):
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
                            item["aggregate_api_key"] = f"u{idx}:{item.get('id', '')}"
                            item["aggregate_upstream_index"] = idx
                            item["aggregate_upstream_base_url"] = bu
                            merged.append(item)
                        else:
                            merged.append(it)
                except Exception:
                    continue
            return jsonify({"object": "list", "data": merged})

        body = parse_body_json()
        req_model = body.get("model", "") if isinstance(body, dict) else ""
        selected_idx = 0
        if isinstance(req_model, str) and req_model.startswith("u") and ":" in req_model:
            prefix, _rest = req_model.split(":", 1)
            if prefix[1:].isdigit():
                idx = int(prefix[1:])
                if 0 <= idx < len(base_urls):
                    selected_idx = idx
        elif req_model in model_to_upstream_idx:
            selected_idx = model_to_upstream_idx[req_model]

        bu = base_urls[selected_idx]
        ak = api_keys[selected_idx]
        url = build_upstream_url(bu, subpath)
        qs = request.query_string.decode("utf-8")
        if qs:
            url = f"{url}?{qs}"

        headers = build_upstream_headers(ak)
        upstream = requests.request(
            method=request.method,
            url=url,
            headers=headers,
            data=request.get_data(),
            allow_redirects=False,
            timeout=UPSTREAM_TIMEOUT,
            stream=True,
        )

        resp_headers = normalize_response_headers(upstream.headers)

        def gen():
            for chunk in upstream.iter_content(chunk_size=8192):
                if chunk:
                    yield chunk

        return Response(gen(), status=upstream.status_code, headers=resp_headers)

    return app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base_url", required=True, help="Comma-separated base URLs")
    parser.add_argument("--api_key", default="", help="Optional comma-separated API keys")
    parser.add_argument("--new_api_key", default="", help="Optional key for this aggregate API")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9400)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    base_urls, api_keys = normalize_upstreams(args.base_url, args.api_key)
    app = create_app(base_urls, api_keys, new_api_key=args.new_api_key or None)

    print(f"[aggregate_apis] listening on http://{args.host}:{args.port}")
    print("[aggregate_apis] routes:")
    print("  - /v1/models (aggregate + refresh model routing map)")
    print("  - /v1/* (route by model, fallback to upstream[0])")
    print("[aggregate_apis] model routing:")
    print("  - exact model id from /models mapping")
    print("  - or aggregate_api_key like u1:model_name")

    app.run(host=args.host, port=args.port, threaded=True, debug=args.debug, use_reloader=args.debug)


if __name__ == "__main__":
    main()
