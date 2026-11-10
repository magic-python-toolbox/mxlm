"""Gemini generateContent API, for the latest Gemini models with thought signatures."""

import json
import mimetypes

from mxlm.api_protocols import post, sort_tool_messages, split_leading_system_messages

GENERATION_CONFIG_KEY_MAPPING = {
    "temperature": "temperature",
    "top_p": "topP",
    "top_k": "topK",
    "candidate_count": "candidateCount",
    "presence_penalty": "presencePenalty",
    "frequency_penalty": "frequencyPenalty",
    "response_mime_type": "responseMimeType",
    "response_schema": "responseSchema",
}


def content_to_parts(content):
    if isinstance(content, str):
        return [{"text": content}]
    parts = []
    for part in content:
        if part["type"] == "text":
            part = {"text": part["text"]}
        elif part["type"] in ["image_url", "audio_url", "video_url"]:
            url = part[part["type"]]["url"]
            if url.startswith("data:"):
                mime_type, data = url[len("data:") :].split(";base64,")
                part = {"inlineData": {"mimeType": mime_type, "data": data}}
            else:
                # Vertex rejects fileData without an explicit mimeType.
                part = {
                    "fileData": {
                        "mimeType": mimetypes.guess_type(url)[0],
                        "fileUri": url,
                    }
                }
        elif part["type"] == "input_audio":
            part = {
                "inlineData": {
                    "mimeType": f"audio/{part['input_audio']['format']}",
                    "data": part["input_audio"]["data"],
                }
            }
        else:
            part = {"text": json.dumps(part, ensure_ascii=False)}
        parts.append(part)
    return parts


def message_to_content(message):
    if message["role"] == "tool":
        content = message["content"]
        if isinstance(content, str):
            content = [{"type": "text", "text": content}]
        function_response = {
            "name": message["name"],
            # Gemini 3+ matches function responses to function calls by id
            "id": message["tool_call_id"],
            "response": {
                "result": "".join(
                    part["text"] for part in content if part["type"] == "text"
                )
            },
        }
        media_parts = [part for part in content if part["type"] != "text"]
        if media_parts:
            function_response["parts"] = content_to_parts(media_parts)
        return {"role": "user", "parts": [{"functionResponse": function_response}]}
    if message["role"] != "assistant":
        return {"role": "user", "parts": content_to_parts(message["content"])}
    signatures = (
        message.get("sidecar", {})
        .get("gemini_generate_content", {})
        .get("thoughtSignatures", {})
    )

    def signed(part, key):
        if key in signatures:
            part["thoughtSignature"] = signatures[key]
        return part

    parts = []
    if message.get("reasoning"):
        parts.append(
            signed({"text": message["reasoning"], "thought": True}, "reasoning.0")
        )
    if message.get("content"):
        parts += content_to_parts(message["content"])
        # The signature of a text-only answer restores its thoughts into the model context.
        signed(parts[-1], "content.0")
    for index, tool_call in enumerate(message.get("tool_calls") or []):
        function_call = {
            "name": tool_call["function"]["name"],
            "args": json.loads(tool_call["function"]["arguments"] or "{}"),
            "id": tool_call["id"],
        }
        parts.append(signed({"functionCall": function_call}, f"tool_calls.{index}"))
    return {"role": "model", "parts": parts}


def create(
    base_url,
    api_key,
    messages,
    model,
    tools=None,
    tool_choice=None,
    max_tokens=None,
    max_completion_tokens=None,
    stop=None,
    top_logprobs=None,
    thinkingConfig=None,
    generationConfig=None,
    stream=False,
    **parameters,
):
    system_messages, messages = split_leading_system_messages(messages)
    generation_config = dict(generationConfig or {})
    for source_key, target_key in GENERATION_CONFIG_KEY_MAPPING.items():
        if parameters.get(source_key) is not None:
            generation_config[target_key] = parameters.pop(source_key)
    if max_tokens or max_completion_tokens:
        generation_config["maxOutputTokens"] = max_tokens or max_completion_tokens
    if stop:
        generation_config["stopSequences"] = [stop] if isinstance(stop, str) else stop
    if top_logprobs:
        generation_config.update(responseLogprobs=True, logprobs=top_logprobs)
    # generateContent only offers on/off thought summaries (no verbosity level), so always opt in unless overridden.
    generation_config["thinkingConfig"] = {
        "includeThoughts": True,
        **(
            thinkingConfig
            or generation_config.get("thinkingConfig")
            or {"thinkingLevel": "HIGH"}
        ),
    }
    body = {**parameters, "contents": [], "generationConfig": generation_config}
    if system_messages:
        body["systemInstruction"] = {
            "parts": [
                part
                for message in system_messages
                for part in content_to_parts(message["content"])
            ]
        }
    for content in map(message_to_content, sort_tool_messages(messages)):
        if body["contents"] and body["contents"][-1]["role"] == content["role"]:
            body["contents"][-1]["parts"] += content["parts"]
        else:
            body["contents"].append(content)
    if tools:
        body["tools"] = [
            {
                "functionDeclarations": [
                    {
                        "name": tool["function"]["name"],
                        "description": tool["function"].get("description", ""),
                        "parametersJsonSchema": tool["function"]["parameters"],
                    }
                    for tool in tools
                ]
            }
        ]
    if tool_choice == "none":
        body["toolConfig"] = {"functionCallingConfig": {"mode": "NONE"}}
    elif tool_choice == "required":
        body["toolConfig"] = {"functionCallingConfig": {"mode": "ANY"}}
    elif isinstance(tool_choice, dict):
        body["toolConfig"] = {
            "functionCallingConfig": {
                "mode": "ANY",
                "allowedFunctionNames": [tool_choice["function"]["name"]],
            }
        }
    response = post(
        f"{base_url}/models/{model}:"
        + ("streamGenerateContent?alt=sse" if stream else "generateContent"),
        {"x-goog-api-key": api_key},
        body,
        stream,
    )
    if not stream:
        return response
    # Merge the chunks to the same parts as non-stream, the stream only keeps the long connection alive.
    parts = []
    for chunk in response:
        if chunk.get("promptFeedback", {}).get("blockReason"):
            return chunk
        candidate = chunk["candidates"][0]
        for part in candidate.get("content", {}).get("parts", []):
            if (
                parts
                and "text" in part
                and "text" in parts[-1]
                and part.get("thought") == parts[-1].get("thought")
            ):
                parts[-1] = {
                    **parts[-1],
                    **part,
                    "text": parts[-1]["text"] + part["text"],
                }
            else:
                parts.append(part)
        if "finishReason" in candidate:
            candidate["content"] = {"role": "model", "parts": parts}
            return chunk
    raise RuntimeError("The stream ended without finishReason")


def response_to_messages(response):
    if response.get("promptFeedback", {}).get("blockReason"):
        # The blocked prompt has no candidates, its reason is only an enum in response["promptFeedback"]
        return [{"role": "assistant", "content": "", "finish_reason": "content_filter"}]
    candidate = response["candidates"][0]
    message = {"role": "assistant", "content": ""}
    signatures = {}
    for part in candidate.get("content", {}).get("parts", []):
        if "functionCall" in part:
            tool_calls = message.setdefault("tool_calls", [])
            key = f"tool_calls.{len(tool_calls)}"
            function_call = part["functionCall"]
            tool_calls.append(
                {
                    "index": len(tool_calls),
                    "id": function_call.get("id")
                    or f"functions.{function_call['name']}:{len(tool_calls)}",
                    "type": "function",
                    "function": {
                        "name": function_call["name"],
                        "arguments": json.dumps(
                            function_call.get("args", {}), ensure_ascii=False
                        ),
                    },
                }
            )
        elif part.get("thought"):
            key = "reasoning.0"
            message["reasoning"] = message.get("reasoning", "") + part["text"]
        else:
            key = "content.0"
            message["content"] += part.get("text", "")
        if "thoughtSignature" in part:
            signatures[key] = part["thoughtSignature"]
    if signatures:
        message["sidecar"] = {
            "gemini_generate_content": {"thoughtSignatures": signatures}
        }
    message["finish_reason"] = (
        "tool_calls"
        if "tool_calls" in message
        else {
            "STOP": "stop",
            "MAX_TOKENS": "length",
            "SAFETY": "content_filter",
            "RECITATION": "content_filter",
            "BLOCKLIST": "content_filter",
            "PROHIBITED_CONTENT": "content_filter",
            "SPII": "content_filter",
            "MALFORMED_FUNCTION_CALL": "tool_calls",
        }.get(candidate["finishReason"], candidate["finishReason"].lower())
    )
    return [message]


if __name__ == "__main__":
    from boxx import tree
    from mxlm.api_protocols import example_chat_api, example_trajectory

    client = example_chat_api("gemini_generate_content")
    new_traj = client(example_trajectory, return_traj=1)
    tree(new_traj)
    stream_traj = client(example_trajectory, return_traj=1, stream=True)
    tree(stream_traj)
