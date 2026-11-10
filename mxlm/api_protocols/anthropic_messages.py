"""Anthropic Messages API, for the latest Claude models with adaptive thinking."""

import json

from mxlm.api_protocols import hash_message, post, split_leading_system_messages


def encode_tool_id(tool_id):
    # Anthropic tool ids must match ^[a-zA-Z0-9_-]+$
    return "".join(
        (
            char
            if char.isascii() and (char.isalnum() or char in "_-")
            else "-_" + {".": "DOT", ":": "COLON"}.get(char, f"U{ord(char):X}") + "_-"
        )
        for char in tool_id
    )


def content_to_anthropic(content):
    if isinstance(content, str):
        return content
    parts = []
    for part in content:
        if part["type"] == "image_url":
            url = part["image_url"]["url"]
            if url.startswith("data:"):
                media_type, data = url[len("data:") :].split(";base64,")
                source = {"type": "base64", "media_type": media_type, "data": data}
            else:
                source = {"type": "url", "url": url}
            part = {"type": "image", "source": source}
        parts.append(part)
    return parts


def message_to_anthropic(message):
    if message["role"] == "tool":
        return {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": encode_tool_id(message["tool_call_id"]),
                    "content": content_to_anthropic(message["content"]),
                }
            ],
        }
    if message["role"] != "assistant":
        return {
            "role": message["role"],
            "content": content_to_anthropic(message["content"]),
        }
    sidecar = message.get("sidecar", {}).get("anthropic_messages", {})
    # A flat message cannot keep the interleaved blocks, so replay the original content unless the message was edited.
    if sidecar.get("message_hash") == hash_message(message):
        # Tool ids are encoded the same as the tool_use_id of tool results
        content = [
            (
                dict(block, id=encode_tool_id(block["id"]))
                if block["type"] == "tool_use"
                else block
            )
            for block in sidecar["content"]
        ]
        return {"role": "assistant", "content": content}
    # Signed thinking keeps its model context, even if the reasoning text was edited.
    content = [
        block
        for block in sidecar.get("content", [])
        if block.get("signature") or block["type"] == "redacted_thinking"
    ]
    if not content and message.get("reasoning"):
        # Reasoning from other sources has no signature, which compatible providers accept.
        content.append({"type": "thinking", "thinking": message["reasoning"]})
    if message.get("content"):
        content.append({"type": "text", "text": message["content"]})
    for tool_call in message.get("tool_calls") or []:
        content.append(
            {
                "type": "tool_use",
                "id": encode_tool_id(tool_call["id"]),
                "name": tool_call["function"]["name"],
                "input": json.loads(tool_call["function"]["arguments"] or "{}"),
            }
        )
    return {"role": "assistant", "content": content}


def create(
    base_url,
    api_key,
    messages,
    tools=None,
    tool_choice=None,
    max_tokens=None,
    max_completion_tokens=None,
    stop=None,
    thinking=None,
    output_config=None,
    stream=False,
    **parameters,
):
    system_messages, messages = split_leading_system_messages(messages)
    thinking = thinking or {"type": "adaptive"}
    body = {
        # Opt in to automatic prompt caching, which other protocols do by default; its breakpoint follows the last block as messages grow.
        "cache_control": {"type": "ephemeral"},
        **parameters,
        "stream": stream,
        "max_tokens": max_tokens or max_completion_tokens or 32 * 1024,
        "messages": [],
        "system": "\n\n".join(message["content"] for message in system_messages)
        or None,
        "stop_sequences": [stop] if isinstance(stop, str) else stop,
        # Chat completions tool_choice: "none", "auto" or "required". Objects are passed through as Anthropic tool_choice.
        "tool_choice": (
            {"type": "any" if tool_choice == "required" else tool_choice}
            if isinstance(tool_choice, str)
            else tool_choice
        ),
        # Only adaptive thinking accepts display
        "thinking": (
            {"display": "summarized", **thinking}
            if thinking["type"] == "adaptive"
            else thinking
        ),
        "output_config": {"effort": "high", **(output_config or {})},
    }
    for message in map(message_to_anthropic, messages):
        if body["messages"] and body["messages"][-1]["role"] == message["role"]:
            body["messages"][-1]["content"] = [
                block
                for content in [body["messages"][-1]["content"], message["content"]]
                for block in (
                    content
                    if isinstance(content, list)
                    else [{"type": "text", "text": content}]
                )
            ]
        else:
            body["messages"].append(message)
    if tools:
        body["tools"] = [
            {
                "name": tool["function"]["name"],
                "description": tool["function"].get("description", ""),
                "input_schema": tool["function"]["parameters"],
            }
            for tool in tools
        ]
    response = post(
        f"{base_url}/messages",
        {"x-api-key": api_key, "anthropic-version": "2023-06-01"},
        body,
        stream,
    )
    if not stream:
        return response
    # Accumulate the events to the same message as non-stream, the stream only keeps the long connection alive.
    for event in response:
        if event["type"] == "message_start":
            message = event["message"]
        elif event["type"] == "content_block_start":
            message["content"].append(event["content_block"])
        elif event["type"] == "content_block_delta":
            block, delta = message["content"][event["index"]], event["delta"]
            key = {
                "text_delta": "text",
                "thinking_delta": "thinking",
                "signature_delta": "signature",
                "input_json_delta": "partial_json",
            }[delta["type"]]
            block[key] = block.get(key, "") + delta[key]
        elif event["type"] == "content_block_stop":
            block = message["content"][event["index"]]
            if "partial_json" in block:
                text = block.pop("partial_json")
                # max_tokens may truncate the input JSON, so keep its complete entries the same as non-stream:
                # cut back at each comma from the end and close the object, the first valid one is them.
                commas = [i for i in range(len(text) - 1, -1, -1) if text[i] == ","]
                for candidate in [
                    text,
                    text + "}",
                    *(text[:i] + "}" for i in commas),
                    "{}",
                ]:
                    try:
                        block["input"] = json.loads(candidate)
                        break
                    except json.JSONDecodeError:
                        pass
        elif event["type"] == "message_delta":
            message.update(event["delta"])
            message["usage"].update(event["usage"])
        elif event["type"] == "message_stop":
            return message
        assert event["type"] != "error", event
    raise RuntimeError("The stream ended without message_stop")


def response_to_messages(response):
    blocks = response["content"]
    message = {
        "role": "assistant",
        "content": "".join(
            block["text"] for block in blocks if block["type"] == "text"
        ),
    }
    reasoning = "\n\n".join(
        block["thinking"] for block in blocks if block["type"] == "thinking"
    )
    if reasoning:
        message["reasoning"] = reasoning
    tool_uses = [block for block in blocks if block["type"] == "tool_use"]
    if tool_uses:
        message["tool_calls"] = [
            {
                "index": index,
                "id": block["id"],
                "type": "function",
                "function": {
                    "name": block["name"],
                    "arguments": json.dumps(block["input"], ensure_ascii=False),
                },
            }
            for index, block in enumerate(tool_uses)
        ]
    message["sidecar"] = {
        "anthropic_messages": {"content": blocks, "message_hash": hash_message(message)}
    }
    if response["stop_reason"] == "refusal":
        message["refusal"] = response["stop_details"]["explanation"]
    message["finish_reason"] = {
        "end_turn": "stop",
        "max_tokens": "length",
        "stop_sequence": "stop",
        "tool_use": "tool_calls",
        "refusal": "content_filter",
    }.get(response["stop_reason"], response["stop_reason"])
    return [message]


if __name__ == "__main__":
    from boxx import tree
    from mxlm.api_protocols import example_chat_api, example_trajectory

    client = example_chat_api("anthropic_messages")
    new_traj = client(example_trajectory, return_traj=1)
    tree(new_traj)
    stream_traj = client(example_trajectory, return_traj=1, stream=True)
    tree(stream_traj)
