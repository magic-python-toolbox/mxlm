import requests
import argparse
from flask import Flask, request, Response
import json

app = Flask(__name__)


def pretty_json(value):
    return json.dumps(value, ensure_ascii=False, indent=2, default=str)


@app.route("/", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def proxy(path=""):
    target_url = f"{args.target.rstrip('/')}/{path}" if path else args.target
    request_query = request.query_string.decode("utf-8")
    if request_query:
        target_url = f"{target_url}?{request_query}"

    body = None
    stream_flag = "text/event-stream" in request.headers.get("Accept", "").lower()

    # Print request information
    print(f"\n{'='*50}")
    print(f"Request Method: {request.method}")
    print(f"Target URL: {target_url}")
    print(f"Request Headers: {pretty_json(dict(request.headers))}")

    if request.data:
        try:
            body = json.loads(request.data)
            print(f"Request Body: {pretty_json(body)}")
            stream_flag = stream_flag or bool(body.get("stream"))
        except:
            print(f"Request Body: {request.data}")

    # Forward request
    resp = requests.request(
        method=request.method,
        url=target_url,
        headers={key: value for key, value in request.headers if key != "Host"},
        data=request.data,
        cookies=request.cookies,
        allow_redirects=True,
        stream=stream_flag,
    )

    if resp.history:
        print("Redirect history:")
        for previous in resp.history:
            location = previous.headers.get("Location", "<unknown>")
            print(f"  {previous.status_code} -> {location}")
        print(f"Final URL: {resp.url}")

    # Print response information
    print(f"\nResponse Status: {resp.status_code}")
    print(f"Response Headers: {pretty_json(dict(resp.headers))}")
    if stream_flag:
        print("Response Body: <streaming response>")
    else:
        try:
            print(f"Response Body: {pretty_json(resp.json())}")
        except:
            print(f"Response Body: {resp.text[:200]}...")
    print(f"{'='*50}\n")

    # Return response
    if stream_flag:
        response = Response(
            (chunk for chunk in resp.iter_content(chunk_size=8192) if chunk),
            resp.status_code,
        )
    else:
        response = Response(resp.content, resp.status_code)
    blocked_headers = {
        "content-length",
        "transfer-encoding",
        "content-encoding",
        "connection",
    }
    for key, value in resp.headers.items():
        if key.lower() in blocked_headers:
            continue
        response.headers[key] = value
    return response


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""
HTTP proxy service for debugging API requests
Forwards requests to the specified API address and prints request and response information.
usage:
    python -m mxlm.server.api_proxy -t 127.0.0.1:58080
"""
    )
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target API address, e.g. http://api.example.com:[port]",
    )
    parser.add_argument("--port", type=int, default=8000, help="Proxy server port")
    args = parser.parse_args()
    if "http" not in args.target:
        args.target = "http://" + args.target
    print(f"API proxy service started at http://localhost:{args.port}")
    print(f"Target API: {args.target}")
    app.run(host="0.0.0.0", port=args.port)
