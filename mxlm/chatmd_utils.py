#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Mar 29 16:15:58 2024

@author: yl
"""
import re
import json

chatmd_temple = """\n\n<!--<|BOT|>--><hr></hr><hr></hr> {tag}
## {role}
{content}"""


def messages_to_chatmd(messages):
    md = ""
    for msg in messages:
        msg_ = {k: msg.get(k, "") for k in ["tag", "role", "content"]}
        if isinstance(msg_["tag"], (dict, list, tuple)):
            msg_["tag"] = json.dumps(msg_["tag"], ensure_ascii=False)
        md += chatmd_temple.format(**msg_)
    return md


def chatmd_to_messages(chatmd):
    pattern = re.compile(
        r"<!--<\|BOT\|>--><hr></hr><hr></hr> *(?P<tag>.*?) *\n##  ?(?P<role>\w*?) *\n(?P<content>.+?)"  # content
        "(?=\n\n<!--<\|BOT\|>--><hr></hr><hr></hr>|$)",
        re.DOTALL,
    )

    messages = []
    for match in pattern.finditer(chatmd):
        content = match.group("content")  # .strip()
        msg = {
            "role": match.group("role"),
            "content": content,
        }
        tag = match.group("tag")
        if tag:
            # Revert to json if tag is json
            is_dict = tag[0] == "{" and tag[-1] == "}" and ":" in tag
            is_list = tag[0] == "[" and tag[-1] == "]"
            if is_dict or is_list:
                tag = json.loads(tag)
            msg["tag"] = tag
        messages.append(msg)
    return messages


if __name__ == "__main__":
    chatmd_example = """

<!--<|BOT|>--><hr></hr><hr></hr> Here you can put the `tag`, must be one line. Could be str or JSON.
## system
You are a helpful assistant.

<!--<|BOT|>--><hr></hr><hr></hr> {"url":"XXX.html", "title":"XXX"}
## context
{text from url}

<!--<|BOT|>--><hr></hr><hr></hr>
## comment
Multi-line comments.  
Visible to humans but invisible to models.

<!--<|BOT|>--><hr></hr><hr></hr>
## user  
Summarize the content in this url: 
https://XXX.html
"""
    msgs = chatmd_to_messages(chatmd_example)
    for msg in msgs:
        print(msg)

    chatmd = messages_to_chatmd(msgs)
    print(chatmd)
