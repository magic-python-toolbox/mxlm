#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Mar 29 16:15:58 2024

@author: yl
"""
import os
import json


def df_to_html(df, *args, max_width=400, HTML_WIDTH_PER_CHAR=8, **argkws):
    """
    Pretty print DataFrame to html
    """
    import html
    import pprint

    if hasattr(df, "to_frame"):
        df = df.to_frame()

    argkws.setdefault(
        "formatters",
        {
            col: lambda x: f'<div style="max-width:{max_width}px;"><span style="white-space: pre-wrap; font-family: Monospace;">%s</span></div>'
            % html.escape(
                pprint.pformat(x, indent=0, width=max_width // HTML_WIDTH_PER_CHAR)
            )
            for col in df.columns
        },
    )
    argkws.setdefault("escape", False)
    return df.to_html(*args, **argkws)


def markdown_escape(text):
    return text.replace("\n", "↳").replace("|", "\|").replace("$", "\$").strip()


def get_text_content(msg):
    if isinstance(msg, dict) and "content" in msg:
        content = msg.get("content", "")
    else:
        content = msg
    if isinstance(content, list):
        content = "".join([c["text"] for c in content])
    return content


def remove_last_assistant(messages):
    while messages[-1]["role"] == "assistant":
        messages = messages[:-1]
    return messages


def remove_system_prompt(messages):
    while messages[0]["role"] == "system":
        messages = messages[1:]
    return messages


def message_to_sequence(message):
    content = message["content"]
    content = content if isinstance(content, str) else json.dumps(content)
    finish_reason = message.get("finish_reason")
    return (
        f"## {message['role']}\n"
        + content
        + (
            f"<|{finish_reason}|>"
            if finish_reason and finish_reason != "length"
            else ""
        )
    )


def messages_to_sequence(messages):
    return "\n\n-----\n\n".join([message_to_sequence(msg) for msg in messages])


def messages_to_condition_key(messages):
    # For duplicate removal
    instructs = ()
    instruct = ()
    for msg in messages:
        if msg["role"] == "assistant":
            instructs += (instruct,)
            instruct = ()
        else:
            instruct += (msg["role"], msg["content"])
    if instruct:
        instructs += (instruct,)
    return instructs


def sanity_check_messages(messages):
    for msg in messages:
        assert "role" in msg, msg
        assert "content" in msg, msg
        assert isinstance(msg["content"], (str, list)), msg
        if "finish_reason" in msg:
            assert isinstance(msg["finish_reason"], str), msg["finish_reason"]
        if "preference_tag" in msg:
            assert msg["preference_tag"] in [None, "chosen", "rejected"], msg[
                "preference_tag"
            ]
    return messages


def bbcode_to_markdown_math(messages):  # inplace
    for msg in messages:
        if msg["role"] == "assistant":
            msg["content"] = (
                msg["content"]
                .replace("\\[ ", "$$")
                .replace(" \\]", "$$")
                .replace("\\( ", "$")
                .replace(" \\)", "$")
                .replace("\\[", "$$")
                .replace("\\]", "$$")
                .replace("\\(", "$")
                .replace("\\)", "$")
            )
    return messages


class ChatRequestCacheManager:
    """
    Cache chat request.
    Index by MD5 of messages and kwargs.
    """

    mxlm_cache_version = 1.0

    def __init__(self, messages, cache, **kwargs):
        import tempfile

        assert cache, cache
        self.messages = messages
        self.kwargs = kwargs
        [
            self.kwargs.pop(key)
            for key in ["stream", "cache", "retry"]
            if key in self.kwargs
        ]
        if isinstance(cache, str):
            self.cache_dir = cache
        else:
            self.cache_dir = os.path.join(tempfile.gettempdir(), "mxlm-tmp/cache")
        os.makedirs(self.cache_dir, exist_ok=True)
        self.cache_path = self.get_cache_path()

    def get_cache_path(self):
        import hashlib

        fname = hashlib.md5(
            str(self.messages + [self.kwargs]).encode("utf-8")
        ).hexdigest()
        cache_path = os.path.join(self.cache_dir, fname + ".json")
        return cache_path

    def is_in_cache(self):
        return os.path.isfile(self.cache_path)

    def get_cache(self):
        with open(self.cache_path, "r") as f:
            dumped_json = json.load(f)
            response = dumped_json["response"]
        return response

    def set_cache(self, d):
        import time

        create_time = "%d-%02d-%02d_%02d:%02d:%02d" % time.localtime(time.time())[:6]
        dumped_json = dict(
            mxlm_cache_version=self.mxlm_cache_version,
            create_time=create_time,
            kwargs=self.kwargs,
            prompt=self.messages,
            response=d,
        )
        with open(self.cache_path, "w", encoding="utf-8") as f:
            json.dump(dumped_json, f, indent=2, ensure_ascii=False)
        return self.cache_path


def hash_object_sha256_base64(obj, sort_keys=True):
    import hashlib
    import base64

    canonical_string = json.dumps(obj, sort_keys=sort_keys, separators=(",", ":"))
    sha256_hash = hashlib.sha256(canonical_string.encode("utf-8")).digest()
    return base64.b64encode(sha256_hash).decode("utf-8")
