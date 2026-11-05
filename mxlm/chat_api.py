#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import copy
import importlib
import json
import os
import time
import urllib.parse
import warnings


_DEBUG_LOG_STRING_LIMIT = 4000
_DEBUG_LOG_STRING_KEEP = 1000


def _pretty_debug_json(value):
    def slim_strings(data):
        if isinstance(data, dict):
            return {key: slim_strings(value) for key, value in data.items()}
        if isinstance(data, (list, tuple)):
            return [slim_strings(value) for value in data]
        if isinstance(data, str) and len(data) > _DEBUG_LOG_STRING_LIMIT:
            return (
                data[:_DEBUG_LOG_STRING_KEEP]
                + f"\n... (omitted {len(data) - 2 * _DEBUG_LOG_STRING_KEEP} chars) ...\n"
                + data[-_DEBUG_LOG_STRING_KEEP:]
            )
        return data

    return json.dumps(slim_strings(value), ensure_ascii=False, indent=2, default=str)


def _write_debug_log(target, text):
    if "/" in target or os.path.splitext(target)[1]:
        with open(target, "a", encoding="utf-8") as f:
            print(text, file=f, flush=True)
    else:
        print(text, flush=True)


def _merge_two_deltas(delta1, delta2, unmerged_keys=()):
    merged = copy.deepcopy(delta1)
    for key, value2 in delta2.items():
        if key not in merged:
            merged[key] = copy.deepcopy(value2)
            continue
        value1 = merged[key]
        if key in unmerged_keys:
            continue
        if isinstance(value1, str) and isinstance(value2, str):
            merged[key] = value1 + value2
        elif isinstance(value1, (int, float)) and isinstance(value2, (int, float)):
            assert value1 == value2, f"Number mismatch: {value1} != {value2}"
        elif isinstance(value1, dict) and isinstance(value2, dict):
            merged[key] = _merge_two_deltas(value1, value2, unmerged_keys)
    return merged


class ChatAPI:
    default_messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Just repeat `mxlm`."},
    ]
    default_base_url = None
    # {(api domain, model): reasoning key}, inferred from openai_chat responses
    reasoning_key_cache = {}

    def __init__(
        self,
        base_url=None,  # try get MXLM_BASE_URL, OPENAI_BASE_URL env
        api_key=None,  # try get OPENAI_API_KEY env
        model=None,
        temperature=None,
        max_tokens=None,
        top_p=None,
        parser=None,  # callable parser to process message dict (reasoning, tool calls, etc.)
        is_reasoning=None,  # is this model a reasoning model.
        protocol="openai_chat",  # "openai_chat" | "openai_responses" | "anthropic_messages" | "gemini_generate_content"
        reasoning_key=None,  # "reasoning" | "reasoning_content" of openai_chat server, None to infer
        **default_kwargs,
    ):
        # import openai as openai
        import mxlm.openai_requests as openai

        OpenAI = openai.OpenAI

        assert openai.__version__ >= "1.0", openai.__version__
        if model is None and base_url and ":" not in base_url and "/" not in base_url:
            base_url, model = model, base_url
        if protocol == "openai_chat":
            temperature = 0.8 if temperature is None else temperature
            # avoid 16k context model error
            max_tokens = 15360 if max_tokens is None else max_tokens
            top_p = 0.95 if top_p is None else top_p
        self.protocol = protocol
        self.reasoning_key = reasoning_key
        self.base_url = (
            base_url
            or os.environ.get("MXLM_BASE_URL")
            or os.environ.get("OPENAI_BASE_URL")
            or self.default_base_url
            or "https://api.openai.com/v1"
        )
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "sk-NoneKey")

        # split kwargs to client's kwargs and call kwargs
        client_kwargs = {
            k: default_kwargs.pop(k)
            for k in list(default_kwargs)
            if k in OpenAI.__init__.__code__.co_varnames
        }

        self.client = OpenAI(
            api_key=self.api_key, base_url=self.base_url, **client_kwargs
        )
        self.default_kwargs = dict(
            model=model or self.get_default_model(),
            temperature=temperature,
            max_tokens=max_tokens,
            top_p=top_p,
        )
        self.default_kwargs.update(default_kwargs)
        self.parser = parser
        self.is_reasoning = is_reasoning  # If set None, it will be automatically set a boolen on the first request

    def get_model_list(self):
        return self.client.models.list().dict()["data"]

    def get_default_model(self):
        return self.get_model_list()[0]["id"]

    @property
    def api_protocol(self):
        return importlib.import_module("mxlm.api_protocols." + self.protocol)

    @staticmethod
    def convert_to_messages(msgs):
        if msgs is None:
            return None
        if isinstance(msgs, str):
            return [{"role": "user", "content": msgs}]
        if isinstance(msgs, dict):
            messages = []
            for role in ["system", "context", "user", "assistant"]:
                if role in msgs:
                    messages.append(dict(role=role, content=msgs[role]))
            return messages
        return msgs

    def get_dict_by_chat_completions(self, messages, **kwargs):
        reasoning_key = self.reasoning_key or self.reasoning_key_cache.get(
            (urllib.parse.urlparse(self.base_url).netloc, kwargs["model"])
        )
        # Send reasoning by the server's key, or by both keys before the key is known
        reasoning_keys = (
            [reasoning_key] if reasoning_key else ["reasoning", "reasoning_content"]
        )
        request_messages = []
        for message in messages:
            # Drop the trajectory-only keys like onPanda
            message = {
                k: v
                for k, v in message.items()
                if k not in ["finish_reason", "sidecar"]
            }
            if "reasoning" in message:
                reasoning = message.pop("reasoning")
                for key in reasoning_keys:
                    message[key] = reasoning
            request_messages.append(message)
        response = self.client.chat.completions.create(
            messages=request_messages, **kwargs
        )
        if kwargs.get("stream"):
            message = {}
            printed_channel = None
            printed_non_content = False
            printed_any = False
            role = None
            chunki = -1
            assert (
                response.response.status_code == 200
            ), f"status_code: {response.response.status_code}"

            def print_stream_text(channel, text):
                nonlocal printed_channel, printed_non_content, printed_any
                if not text:
                    return
                if channel == "content" and not printed_non_content:
                    print(text, end="", flush=True)
                    printed_any = True
                    return
                if printed_channel != channel:
                    if printed_any:
                        print()
                    print(f"<|{channel}|>")
                    printed_channel = channel
                if channel != "content":
                    printed_non_content = True
                print(text, end="", flush=True)
                printed_any = True

            for chunki, _chunk in enumerate(response):
                chunk = _chunk.dict()
                assert "error" not in chunk, chunk
                if len(chunk["choices"]):
                    delta = chunk["choices"][0]["delta"]
                    for key, value in delta.items():
                        if value is None:
                            continue
                        if key == "tool_calls":
                            if not value:
                                continue
                            tool_calls = message.get("tool_calls", [])
                            for tool_call in value:
                                index = tool_call["index"]
                                function = tool_call.get("function", {})
                                print_stream_text(
                                    f"tool_call[{index}].function.name",
                                    function.get("name"),
                                )
                                print_stream_text(
                                    f"tool_call[{index}].function.arguments",
                                    function.get("arguments"),
                                )
                                if index == len(tool_calls):
                                    tool_calls.append(copy.deepcopy(tool_call))
                                else:
                                    tool_calls[index] = _merge_two_deltas(
                                        tool_calls[index], tool_call, ["type", "id"]
                                    )
                            message["tool_calls"] = tool_calls
                            continue
                        if key == "reasoning_details":
                            if not value:
                                continue
                            message["reasoning_details"] = [
                                _merge_two_deltas(
                                    (message.get("reasoning_details") or [{}])[0],
                                    value[0],
                                    ["type", "format"],
                                )
                            ]
                            for detail in value:
                                for detail_key in ["text", "content", "summary"]:
                                    print_stream_text(
                                        f"reasoning_details.{detail_key}",
                                        detail.get(detail_key),
                                    )
                            continue
                        if key == "sidecar":
                            continue
                        if key == "role":
                            role = value
                            continue
                        if isinstance(value, str):
                            message[key] = message.get(key, "") + value
                            if key in ["content", "reasoning", "reasoning_content"]:
                                print_stream_text(key, value)
                            continue
                        message[key] = copy.deepcopy(value)
                    valide_chunk = chunk
            d = valide_chunk.copy()
            d["choices"][0].pop("delta")
            message["content"] = message.get("content", "")
            message["role"] = role or "assistant"
            d["choices"][0]["message"] = {
                key: value
                for key, value in message.items()
                if key in ["role", "content"] or value != ""
            }
            finish_reason_str = f"<|{d['choices'][0]['finish_reason']}|>"
            token_usage_str = (
                f", tokens: {d['usage']['prompt_tokens']}+{d['usage']['completion_tokens']}={d['usage']['total_tokens']}"
                if d.get("usage")
                else ""
            )
            if d.get("usage") and "cached_tokens" in d.get("usage", {}):
                token_usage_str += f" (cached {d['usage']['cached_tokens']})"
            model_str = f'@"{d["model"]}"' if "model" in d else ""
            print(finish_reason_str)
            print()
            print(
                model_str + token_usage_str,
            )
        else:
            d = response.dict()
        return d

    def get_dict_by_completions(self, messages, **kwargs):  # Legacy
        import requests

        kwargs["prompt"] = (
            messages
            if isinstance(messages[-1], str)
            else to_chatml(messages[-1]["content"])  # Not Implemented
        )
        kwargs["stop"] = kwargs.get("stop", [{"token": "<|EOT|>"}])
        assert not kwargs.get("stream"), "NotImplementedError"
        completion_url = os.path.join(self.base_url, "completions")
        # stop_id: 2
        rsp = requests.post(completion_url, json=kwargs)
        assert rsp.status_code == 200, (rsp.status_code, rsp.text)
        d = rsp.json()
        # from boxx import tree
        # tree([kwargs,d])
        if "choices" in d:
            if "message" not in d:
                d["choices"][0]["message"] = dict(content=d["choices"][0]["text"])
        return d

    def prefill_logprobs(self, messages):
        from .prefill_logprobs import compute_prefill_logprobs

        return compute_prefill_logprobs(self, messages)

    def __call__(
        self,
        messages=None,
        return_messages=False,
        return_dict=False,
        return_traj=None,
        **kwargs_,
    ):
        """
        messages support str, dict for convenient single-round dialogue, e.g.:
        >>> client("Tell me a joke.")
        >>> client(
            {
                "system": "you are a helpful assistant.",
                "user": "Tell me a joke."
                }
            )
        messages also support trajectory: {"messages": [...], "tools": [...] (optional)}
        Returns new message.content by default

        - return_traj=True returns dict(trajectory, new_message_count, response) for rollout:
            The new trajectory appends 1~n new assistant messages in chat completions format,
            the protocol-specific data for exact replay is kept in message["sidecar"] like onPanda.
            The response is the raw response, response["protocol"] tells its protocol.
            Append tool messages in the order of the tool calls, since some models match tool results
            by position instead of tool_call_id (openai_responses and gemini_generate_content sort them).
        - continue_final_message=True (openai_chat only) continues the flat final assistant message,
            the new message is the complete one, which replaces the final message
        - Support old completions API when set `completions=True`
        - Support cache when set `cache=True`, cache at /tmp/mxlm-tmp/cache
        """
        from mxlm.mxlm_utils import ChatRequestCacheManager

        messages = messages or self.default_messages
        if isinstance(messages, dict) and "messages" in messages:  # trajectory
            assert "tools" not in kwargs_, "Tools should be in the trajectory"
            if messages.get("tools"):
                kwargs_["tools"] = messages["tools"]
            messages = messages["messages"]
        messages = self.convert_to_messages(messages)

        kwargs = self.default_kwargs.copy()
        kwargs.update(kwargs_)
        if kwargs.get("continue_final_message"):
            assert (
                self.protocol == "openai_chat"
            ), "Only openai_chat supports continue_final_message"
            assert (
                not messages[-1].get("reasoning") and not messages[-1].get("tool_calls")
            ), "Only the flat final message without reasoning and tool_calls can be continued for now"
        is_completions = kwargs.pop("completions") if "completions" in kwargs else False
        if not is_completions:
            for message in messages:
                assert "role" in message and "content" in message, message
        if "stream" in kwargs:
            kwargs["stream"] = bool(kwargs["stream"])

        retry = kwargs.pop("retry") if "retry" in kwargs else 6
        cache = kwargs.pop("cache") if "cache" in kwargs else False
        log_target = os.environ.get("MXLM_CHAT_API_LOG_PATH")
        if log_target is not None:
            endpoint = "completions" if is_completions else "chat/completions"
            if self.protocol != "openai_chat":
                endpoint = self.protocol
            _write_debug_log(
                log_target,
                f"\n{'='*50}\n"
                "Request Method: POST\n"
                f"Target URL: {self.base_url.rstrip('/')}/{endpoint}\n"
                f"Request Body: {_pretty_debug_json(dict(messages=messages, **kwargs))}",
            )
        if cache:
            # Keep cache keys of openai_chat unchanged
            cache_kwargs = (
                kwargs
                if self.protocol == "openai_chat"
                else dict(kwargs, protocol=self.protocol)
            )
            cache_manager = ChatRequestCacheManager(messages, cache, **cache_kwargs)
            in_cache = cache_manager.is_in_cache()
        if cache and in_cache:
            d = cache_manager.get_cache()
        else:
            for tryi in range(retry):
                try:
                    if is_completions:
                        # By `requests.post`
                        d = self.get_dict_by_completions(messages, **kwargs)
                    elif self.protocol == "openai_chat":
                        # By `openai.ChatCompletion.create`
                        d = self.get_dict_by_chat_completions(messages, **kwargs)
                    else:
                        d = self.api_protocol.create(
                            self.base_url, self.api_key, messages, **kwargs
                        )
                    break
                except Exception as e:
                    if tryi == retry - 1:
                        raise e
                    warnings.warn(
                        f"An exception at retry {tryi}/{retry} of {kwargs['model']}: {repr(e)}"
                    )
                    time.sleep(2**tryi)

        if cache and not in_cache:
            cache_manager.set_cache(d)
        if log_target is not None:
            _write_debug_log(
                log_target,
                f"\nResponse Body: {_pretty_debug_json(d)}\n{'='*50}\n",
            )
        d["protocol"] = self.protocol
        if kwargs.get("continue_final_message") and kwargs.get("echo"):
            # ensure echo=True is effective for old API, only as a backup since `startswith` may misjudge: A continuation repeating the prefix is taken as echoed, losing the prefix
            prefix = messages[-1].get("content")
            response_content = d["choices"][0]["message"].get("content") or ""
            if isinstance(prefix, str) and not response_content.startswith(prefix):
                d["choices"][0]["message"]["content"] = prefix + response_content
        if self.protocol == "openai_chat":
            message = dict(
                d["choices"][0]["message"],
                finish_reason=d["choices"][0]["finish_reason"],
            )
            reasoning_keys = [
                key
                for key in ["reasoning", "reasoning_content"]
                if isinstance(message.get(key), str)
            ]
            if len(reasoning_keys) == 1:
                self.reasoning_key_cache[
                    (urllib.parse.urlparse(self.base_url).netloc, kwargs["model"])
                ] = reasoning_keys[0]
            # Trajectory data only keeps `reasoning`
            reasoning_content = message.pop("reasoning_content", None)
            if isinstance(reasoning_content, str):
                message["reasoning"] = message.get("reasoning") or reasoning_content
            # Drop empty fields like the stream mode, e.g. `"reasoning": null` and `"tool_calls": []`,
            # since a present key means a channel to onPanda
            message = {
                key: value
                for key, value in message.items()
                if key in ["role", "content"] or value
            }
            # Some servers finish tool calls with "stop"
            if message.get("tool_calls") and message.get("finish_reason") == "stop":
                message["finish_reason"] = "tool_calls"
            new_messages = [message]
        else:
            new_messages = self.api_protocol.response_to_messages(d)
        message = new_messages[-1]
        if kwargs.get("continue_final_message"):
            # The new message continues the final message, so merge them into the complete one
            if not kwargs.get("echo"):  # echo has prepended the final content
                message["content"] = messages[-1]["content"] + (
                    message.get("content") or ""
                )
            messages = messages[:-1]
        if self.is_reasoning is None and (
            message.get("content") or message.get("tool_calls")
        ):
            self.is_reasoning = any(
                key in message
                for key in ["reasoning", "reasoning_content", "reasoning_details"]
            )
        if callable(self.parser):
            new_messages = [self.parser(message) for message in new_messages]
            if self.protocol == "openai_chat":
                # Keep the parsed message in the response for return_dict
                d["choices"][0]["message"] = new_messages[-1]
        if return_traj:
            trajectory = dict(messages=messages + new_messages)
            if "tools" in kwargs:
                trajectory["tools"] = kwargs["tools"]
            return dict(
                trajectory=trajectory,
                new_message_count=len(new_messages),
                response=d,
            )
        if return_messages or return_dict:
            d["new_messages"] = messages + new_messages
            if return_dict:
                return d
            elif return_messages:
                return d["new_messages"]
        return new_messages[-1]["content"]

    @property
    def model(self):
        return self.default_kwargs.get("model")

    def __str__(self):
        kwargs_str = json.dumps(self.default_kwargs, indent=2)
        return f"mxlm.ChatAPI{tuple([self.base_url])}:\n{kwargs_str[2:-2]}"

    __repr__ = __str__

    @classmethod
    def free_api(
        cls,
        api_key="ak-onPandaTestKey",
        base_url="https://vllm-test-api.diyer22.com/v1",
        stream=True,
        **kwargs,
    ):
        return cls(api_key=api_key, base_url=base_url, stream=stream, **kwargs)


if __name__ == "__main__":
    from boxx import tree
    from mxlm.api_protocols import example_chat_api, example_trajectory

    client = example_chat_api("openai_chat")
    print(client)
    msg = client(stream=True)
    # print(msg)
    new_traj = client(example_trajectory, return_traj=1)
    tree(new_traj)
    stream_traj = client(example_trajectory, return_traj=1, stream=True)
    tree(stream_traj)
