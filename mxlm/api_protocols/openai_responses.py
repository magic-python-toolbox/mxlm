"""OpenAI Responses API in stateless mode: reasoning is replayed by encrypted_content."""

from mxlm.api_protocols import hash_message, post, sort_tool_messages


def content_to_responses(content):
    if isinstance(content, str):
        return content
    parts = []
    for part in content:
        if part["type"] == "text":
            part = {"type": "input_text", "text": part["text"]}
        elif part["type"] == "image_url":
            image_url = part["image_url"]
            part = {
                "type": "input_image",
                "image_url": image_url["url"],
                "detail": image_url.get("detail", "auto"),
            }
        parts.append(part)
    return parts


def message_to_input(message):
    if message["role"] == "tool":
        return [
            {
                "type": "function_call_output",
                "call_id": message["tool_call_id"],
                "output": content_to_responses(message["content"]),
            }
        ]
    if message["role"] != "assistant":
        return [
            {
                "role": message["role"],
                "content": content_to_responses(message["content"]),
            }
        ]
    sidecar = message.get("sidecar", {}).get("openai_responses", {})
    # A flat message cannot keep the interleaved items, so replay the original output unless the message was edited.
    if sidecar.get("message_hash") == hash_message(message):
        return sidecar["output"]
    reasoning_items = [
        item for item in sidecar.get("output", []) if item["type"] == "reasoning"
    ]
    items = [item for item in reasoning_items if item.get("encrypted_content")]
    if not items and reasoning_items and message.get("reasoning"):
        # Open models return raw reasoning text instead of encrypted_content, so replay the edited text.
        # Reasoning from other sources is dropped: OpenAI rejects reasoning items with raw text.
        items.append(
            {
                "type": "reasoning",
                "summary": [],
                "content": [{"type": "reasoning_text", "text": message["reasoning"]}],
            }
        )
    if message.get("content"):
        items.append(
            {
                "role": "assistant",
                "content": message["content"],
                "phase": sidecar.get("phase"),
            }
        )
    for tool_call in message.get("tool_calls") or []:
        items.append(
            {
                "type": "function_call",
                "call_id": tool_call["id"],
                "name": tool_call["function"]["name"],
                "arguments": tool_call["function"]["arguments"],
            }
        )
    return items


def create(
    base_url,
    api_key,
    messages,
    tools=None,
    max_tokens=None,
    max_completion_tokens=None,
    reasoning_effort=None,
    stream=False,
    **parameters,
):
    reasoning = parameters.pop("reasoning", {})
    body = {
        # Stateless mode: reasoning is replayed by encrypted_content instead of server-stored items.
        "store": False,
        "include": ["reasoning.encrypted_content"],
        **parameters,
        "stream": stream,
        "input": [
            item
            for message in sort_tool_messages(messages)
            for item in message_to_input(message)
        ],
        "max_output_tokens": max_tokens or max_completion_tokens,
    }
    # `reasoning=None` omits the parameter, for servers that reject or hang on it.
    if reasoning is not None:
        body["reasoning"] = {
            "effort": reasoning_effort or "xhigh",
            "summary": "detailed",
            **reasoning,
        }
    if tools:
        # Responses API treats an omitted strict as true, which forces optional parameters to be required.
        body["tools"] = [
            {"type": "function", "strict": False, **tool["function"]} for tool in tools
        ]
    response = post(
        f"{base_url}/responses", {"Authorization": f"Bearer {api_key}"}, body, stream
    )
    if not stream:
        return response
    # Deltas only keep the long connection alive, the final event carries the complete response.
    for event in response:
        if event["type"] in ["response.completed", "response.incomplete"]:
            return event["response"]
        assert event["type"] not in ["response.failed", "error"], event
    raise RuntimeError("The stream ended without the final response")


def response_to_messages(response):
    # Split output like r-c-r-c-r-final into 3 assistant messages: each commentary or final answer with its reasoning
    groups = [[]]
    for item in response["output"]:
        if item["type"] in ["reasoning", "message"] and any(
            grouped["type"] == "message" for grouped in groups[-1]
        ):
            groups.append([])
        # Item ids are dropped: with store=False they cannot be resolved by the server.
        groups[-1].append({key: value for key, value in item.items() if key != "id"})
    messages = []
    for items in groups:
        message_items = [item for item in items if item["type"] == "message"]
        message = {
            "role": "assistant",
            "content": "\n\n".join(
                part["text"]
                for item in message_items
                for part in item["content"]
                if part["type"] == "output_text"
            ),
        }
        refusal = "\n\n".join(
            part["refusal"]
            for item in message_items
            for part in item["content"]
            if part["type"] == "refusal"
        )
        if refusal:
            message["refusal"] = refusal
        reasoning = "\n\n".join(
            part["text"]
            for item in items
            if item["type"] == "reasoning"
            for part in item["summary"] + (item.get("content") or [])
        )
        if reasoning:
            message["reasoning"] = reasoning
        function_calls = [item for item in items if item["type"] == "function_call"]
        if function_calls:
            message["tool_calls"] = [
                {
                    "index": index,
                    "id": item["call_id"],
                    "type": "function",
                    "function": {"name": item["name"], "arguments": item["arguments"]},
                }
                for index, item in enumerate(function_calls)
            ]
        message["sidecar"] = {
            "openai_responses": {
                "output": items,
                "message_hash": hash_message(message),
                # "commentary" or "final_answer"
                "phase": message_items[0].get("phase") if message_items else None,
            }
        }
        messages.append(message)
    if response["status"] == "incomplete":
        reason = response["incomplete_details"]["reason"]
        messages[-1]["finish_reason"] = {"max_output_tokens": "length"}.get(
            reason, reason
        )
    else:
        messages[-1]["finish_reason"] = (
            "tool_calls" if "tool_calls" in messages[-1] else "stop"
        )
    return messages


if __name__ == "__main__":
    from boxx import tree
    from mxlm.api_protocols import example_chat_api, example_trajectory

    client = example_chat_api("openai_responses")
    new_traj = client(example_trajectory, return_traj=1)
    tree(new_traj)
    stream_traj = client(example_trajectory, return_traj=1, stream=True)
    tree(stream_traj)
