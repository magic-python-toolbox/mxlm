#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os


class ChatAPI:
    default_messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Just repeat `mxlm`."},
    ]
    default_base_url = None

    def __init__(
        self,
        base_url=None,
        api_key=None,  # try get OPENAI_API_KEY env
        model=None,
        temperature=0.5,
        max_tokens=1024,
        top_p=0.9,
        **default_kwargs,
    ):
        from openai import OpenAI

        self.base_url = base_url or self.default_base_url
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
        return self.get_model_list()[-1]["id"]

    @staticmethod
    def convert_to_messages(msgs):
        if msgs is None:
            return None
        if isinstance(msgs, str):
            return [{"role": "user", "content": msgs}]
        if isinstance(msgs, dict):
            messages = []
            for role in ["system", "context", "user"]:
                if role in msgs:
                    messages.append(dict(role=role, context=msgs[role]))
            return messages
        return msgs

    def __call__(
        self, messages=None, return_messages=False, return_dict=False, **kwargs_
    ):
        """
        messages support str, dict for convenient, e.g.:
        >>> client("Tell me a joke.")
        >>> client(
            {
                "system": "you are a helpful assistant.",
                "context": "Here are some examples of jokes...",
                "user": "Tell me a joke."
                }
            )
        Returns new message.content by default
        """
        messages = messages or self.default_messages
        messages = self.convert_to_messages(messages)
        kwargs = self.default_kwargs.copy()
        kwargs.update(kwargs_)
        if "stream" in kwargs:
            kwargs["stream"] = bool(kwargs["stream"])
        response = self.client.chat.completions.create(messages=messages, **kwargs)

        if kwargs.get("stream"):
            content = ""
            chunki = -1
            for tryi in range(
                1, 15
            ):  # TODO: remove this Temporary solution for empty stream
                for chunki, chunk in enumerate(response):
                    if not chunki:
                        role = chunk.choices[0].delta.role
                    delta = chunk.choices[0].delta.content
                    if delta:
                        content += delta
                        print(delta, end="")
                if chunki == -1:
                    # print("retry!"*5)
                    import warnings

                    warnings.warn(
                        f"Empty stream, ChatAPI retry {tryi}st time",
                        category=UserWarning,
                    )
                    response = self.client.chat.completions.create(
                        messages=messages, **kwargs
                    )
                else:
                    break
            chunk.choices[0].message = chunk.choices[0].delta
            del chunk.choices[0].delta
            chunk.choices[0].message.content = content
            chunk.choices[0].message.role = role
            response = chunk
            print(f"<|{response.choices[0].finish_reason}|>")
        # assert response.status_code == 200, response.status_code
        if return_messages or return_dict:
            d = response.dict()
            d["new_messages"] = messages + [d["choices"][0]["message"]]
            if return_dict:
                return d
            elif return_messages:
                return d["new_messages"]
        return response.choices[0].message.content

    def __str__(self):
        import json

        kwargs_str = json.dumps(self.default_kwargs, indent=2)
        return f"mxlm.ChatAPI{tuple([self.base_url])}:\n{kwargs_str[2:-2]}"

    __repr__ = __str__


if __name__ == "__main__":
    # from boxx import *

    client = ChatAPI()
    print(client)
    msg = client(stream=True)
    # print(msg)
