import requests
import argparse
from flask import Flask, request, Response
import json

app = Flask(__name__)


@app.route("/", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def proxy(path=""):
    target_url = f"{args.target}/{path}"

    # Print request information
    print(f"\n{'='*50}")
    print(f"Request Method: {request.method}")
    print(f"Target URL: {target_url}")
    print(f"Request Headers: {dict(request.headers)}")

    if request.data:
        try:
            body = json.loads(request.data)
            print(f"Request Body: {json.dumps(body, ensure_ascii=False, indent=2)}")
        except:
            print(f"Request Body: {request.data}")

    # Forward request
    resp = requests.request(
        method=request.method,
        url=target_url,
        headers={key: value for key, value in request.headers if key != "Host"},
        data=request.data,
        cookies=request.cookies,
        allow_redirects=False,
    )

    # Print response information
    print(f"\nResponse Status: {resp.status_code}")
    print(f"Response Headers: {dict(resp.headers)}")
    try:
        print(f"Response Body: {json.dumps(resp.json(), ensure_ascii=False, indent=2)}")
    except:
        print(f"Response Body: {resp.text[:200]}...")
    print(f"{'='*50}\n")

    # Return response
    response = Response(resp.content, resp.status_code)
    for key, value in resp.headers.items():
        response.headers[key] = value
    return response


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""
HTTP proxy service for debugging API requests
Forwards requests to the specified API address and prints request and response information.
usage:
    python -m mxlm.api_proxy -t 127.0.0.1:58080
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
