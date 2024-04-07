#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class ChatAPI:
    default_messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Just repeat `mxlm`."},
    ]
    default_base_url = None

    def __init__(self, base_url=None, api_key="sk-NoneKey", **default_argkws):
        from openai import OpenAI

        self.base_url = base_url or self.default_base_url
        self.api_key = api_key
        self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)
        self.default_argkws = dict(
            model=self.get_default_model(),
            max_tokens=1024,
            top_p=0.9,
            temperature=0.5,
        )
        self.default_argkws.update(default_argkws)

    def get_model_list(self):
        return self.client.models.list().dict()["data"]

    def get_default_model(self):
        return self.get_model_list()[-1]["id"]

    def __call__(
        self, messages=None, return_messages=False, return_dict=False, **argkws_
    ):
        """
        Returns new message.content by default
        """
        messages = messages or self.default_messages
        argkws = self.default_argkws.copy()
        argkws.update(argkws_)
        response = self.client.chat.completions.create(messages=messages, **argkws)

        if argkws.get("stream"):
            content = ""
            for chunki, chunk in enumerate(response):
                if not chunki:
                    role = chunk.choices[0].delta.role
                delta = chunk.choices[0].delta.content
                if delta:
                    content += delta
                    print(delta, end="")
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

        argkws_str = json.dumps(self.default_argkws, indent=2)
        return f"mxlm.ChatAPI{tuple([self.base_url])}:\n{argkws_str[2:-2]}"

    __repr__ = __str__


if __name__ == "__main__":
    from boxx import *

    client = ChatAPI()
    print(client)
    msg = client(stream=True)
    # print(msg)
