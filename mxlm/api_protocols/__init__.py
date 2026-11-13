"""
Protocols for `mxlm.ChatAPI(protocol=...)` other than "openai_chat", ported from [onPanda's apiProtocols](https://github.com/on-panda/on-panda/tree/main/src/utils/apiProtocols/).

Each module converts chat completions messages to its request by `create()`,
and converts its raw response to new assistant messages by `response_to_messages()`.
Protocol-specific data for exact replay is kept in `message["sidecar"]`, the same as onPanda.
"""

import itertools
import json
import os

import requests

from mxlm.mxlm_utils import hash_object_sha256_base64
from mxlm.openai_requests import DEFAULT_TIMEOUT

example_trajectory = {
    "messages": [
        {"role": "system", "content": "You are a weather inquiry agent."},
        {
            "role": "user",
            "content": "Say hi first, and then call the tool to tell me the current temperatures(°C) in New York City and San Francisco?",
        },
    ],
    "tools": [
        {
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "Get the current weather in a given location",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "location": {
                            "type": "string",
                            "description": "City and state, e.g., 'San Francisco, CA'",
                        },
                        "unit": {"type": "string", "enum": ["celsius", "fahrenheit"]},
                    },
                    "required": ["location", "unit"],
                },
            },
        }
    ],
}


mcp_trajectory = {
    "messages": [{"role": "user", "content": "What is StepFun's latest main model?"}],
    "tool_configs": [{"type": "mcp", "server_url": "https://mcp.exa.ai/mcp"}],
}


def example_chat_api(protocol):
    """ChatAPI configured by .env.local, e.g. OPENAI_RESPONSES_BASE_URL, for __main__ tests"""
    from dotenv import load_dotenv, find_dotenv
    from mxlm import ChatAPI

    load_dotenv(find_dotenv(".env.local"))
    prefix = protocol.upper()
    return ChatAPI(
        os.environ[f"{prefix}_BASE_URL"],
        os.environ[f"{prefix}_API_KEY"],
        os.environ[f"{prefix}_MODEL"],
        protocol=protocol,
    )


def post(url, headers, body, stream=False):
    # Omit null fields, so None means the server default
    response = requests.post(
        url,
        headers=headers,
        json={key: value for key, value in body.items() if value is not None},
        timeout=DEFAULT_TIMEOUT,
        stream=stream,
    )
    if not response.ok:
        raise RuntimeError(
            f"Failed to fetch {url}: {response.status_code} – {response.text}"
        )
    if stream:
        # JSON events of the server-sent events
        return (
            json.loads(line[len(b"data:") :])
            for line in response.iter_lines()
            if line.startswith(b"data:")
        )
    return response.json()


def split_leading_system_messages(messages):
    count = next(
        (i for i, message in enumerate(messages) if message["role"] != "system"),
        len(messages),
    )
    assert all(
        message["role"] != "system" for message in messages[count:]
    ), "Only leading system messages are supported by this protocol"
    return messages[:count], messages[count:]


def sort_tool_messages(messages):
    # Sort each run of tool messages in the order of the tool calls of its preceding assistant messages,
    # since some models (e.g. GPT by Responses, Gemini) match tool results by position.
    # Tool call ids are only unique in one response, e.g. Gemini's "functions.<name>:<index>".
    sorted_messages, order = [], {}
    for role, run in itertools.groupby(messages, key=lambda message: message["role"]):
        run = list(run)
        if role == "assistant":
            # Consecutive assistant messages are one response, e.g. the split Responses output
            tool_calls = [
                tool_call
                for message in run
                for tool_call in message.get("tool_calls") or []
            ]
            order = {
                tool_call["id"]: index for index, tool_call in enumerate(tool_calls)
            }
        elif role == "tool":
            run.sort(key=lambda message: order[message["tool_call_id"]])
        sorted_messages += run
    return sorted_messages


def hash_message(message):
    # Same as onPanda's hashMessageOutput, to detect edits before replaying the raw output in sidecar
    return hash_object_sha256_base64(
        {
            key: message[key]
            for key in ["reasoning", "content", "tool_calls"]
            if key in message
        }
    )
