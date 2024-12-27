#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import time
import warnings


class ChatAPI:
    default_messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Just repeat `mxlm`."},
    ]
    default_base_url = None

    def __init__(
        self,
        base_url=None,  # try get OPENAI_BASE_URL env
        api_key=None,  # try get OPENAI_API_KEY env
        model=None,
        temperature=0.5,
        max_tokens=1920,  # avoid 2k context model error
        top_p=0.9,
        **default_kwargs,
    ):
        import openai
        from openai import OpenAI

        assert openai.__version__ >= "1.0", openai.__version__
        if model is None and base_url and ":" not in base_url and "/" not in base_url:
            base_url, model = model, base_url
        self.base_url = (
            base_url or self.default_base_url or os.environ.get("OPENAI_BASE_URL")
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

    def get_model_list(self):
        return self.client.models.list().dict()["data"]

    def get_default_model(self):
        return self.get_model_list()[0]["id"]

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
        response = self.client.chat.completions.create(messages=messages, **kwargs)
        if kwargs.get("stream"):
            content = ""
            chunki = -1
            assert (
                response.response.status_code == 200
            ), f"status_code: {response.response.status_code}"
            for chunki, chunk in enumerate(response):
                if not chunki:
                    role = chunk.choices[0].delta.role
                if len(chunk.choices):
                    delta = chunk.choices[0].delta.content
                    if delta:
                        content += delta
                        print(delta, end="")
            d = chunk.dict()
            d["choices"][0]["message"] = d["choices"][0].pop("delta")
            d["choices"][0]["message"]["content"] = content
            d["choices"][0]["message"]["role"] = role
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
            else to_chatml(messages[-1]["content"])
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

    def __call__(
        self, messages=None, return_messages=False, return_dict=False, **kwargs_
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
        Returns new message.content by default

        - Support old completions API when set `completions=True`
        - Support cache when set `cache=True`, cache at /tmp/mxlm-tmp/cache
        """
        from mxlm.mxlm_utils import ChatRequestCacheManager

        messages = messages or self.default_messages
        messages = self.convert_to_messages(messages)

        kwargs = self.default_kwargs.copy()
        kwargs.update(kwargs_)
        is_completions = kwargs.pop("completions") if "completions" in kwargs else False
        if not is_completions:
            for message in messages:
                assert "role" in message and "content" in message, message
        if "stream" in kwargs:
            kwargs["stream"] = bool(kwargs["stream"])

        retry = kwargs.pop("retry") if "retry" in kwargs else 6
        cache = kwargs.pop("cache") if "cache" in kwargs else False
        if cache:
            cache_manager = ChatRequestCacheManager(messages, cache, **kwargs)
            in_cache = cache_manager.is_in_cache()
        if cache and in_cache:
            d = cache_manager.get_cache()
        else:
            for tryi in range(retry):
                try:
                    if is_completions:
                        # By `requests.post`
                        d = self.get_dict_by_completions(messages, **kwargs)
                    else:
                        # By `openai.ChatCompletion.create`
                        d = self.get_dict_by_chat_completions(messages, **kwargs)
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
        if return_messages or return_dict:
            d["new_messages"] = messages + [d["choices"][0]["message"]]
            if return_dict:
                return d
            elif return_messages:
                return d["new_messages"]
        return d["choices"][0]["message"]["content"]

    @property
    def model(self):
        return self.default_kwargs.get("model")

    def __str__(self):
        import json

        kwargs_str = json.dumps(self.default_kwargs, indent=2)
        return f"mxlm.ChatAPI{tuple([self.base_url])}:\n{kwargs_str[2:-2]}"

    __repr__ = __str__

    @classmethod
    def free_api(
        cls,
        api_key=None,
        base_url="https://open.bigmodel.cn/api/paas/v4/",
        model="glm-4-flash",
        stream=True,
        **kwargs,
    ):
        """
        Free API: The current choice for the free ChatAPI is glm-4-flash, which requires users to apply for an api_key.
        """
        if api_key is None:
            assert (
                "ZHIPUAI_API_KEY" in os.environ
            ), "Please apply for a ZHIPUAI_API_KEY and set it as an environment variable, or pass it in through the api_key parameter."
            api_key = os.environ["ZHIPUAI_API_KEY"]
        return cls(
            api_key=api_key, base_url=base_url, model=model, stream=stream, **kwargs
        )


if __name__ == "__main__":
    # from boxx import *

    client = ChatAPI()
    print(client)
    msg = client(stream=True)
    # print(msg)
