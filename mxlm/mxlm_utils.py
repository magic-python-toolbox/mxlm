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


def remove_last_assistant(messages):
    while messages[-1]["role"] == "assistant":
        messages = messages[:-1]
    return messages


def remove_system_prompt(messages):
    while messages[0]["role"] == "system":
        messages = messages[1:]
    return messages


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
            d = json.load(f)
        return d

    def set_cache(self, d):
        with open(self.cache_path, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2, ensure_ascii=False)
        return self.cache_path
