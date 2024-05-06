#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Apr 20 22:06:16 2024

@author: yl
"""


def messages_to_llama2_chat(messages):
    """
    Warnning: instuct Llama2 will genrate two blanks after [\INST].
    Which means it better to do output.lstrip() to remove blanks ahead anwser

    https://llama.meta.com/docs/model-cards-and-prompt-formats/meta-llama-2
    https://replicate.com/meta/llama-2-70b-chat
    https://gpus.llm-utils.org/llama-2-prompt-template/
    https://huggingface.co/blog/llama2#how-to-prompt-llama-2

    the first <s> may added automated by tonkenizer but `<s><s>` won't change result when temperature=0
    """
    B_INST, E_INST = "[INST]", "[/INST]"
    B_SYS, E_SYS = "<<SYS>>\n", "\n<</SYS>>\n\n"
    if messages[0]["role"] == "system":
        messages = [
            {
                "role": messages[1]["role"],
                "content": B_SYS
                + messages[0]["content"]
                + E_SYS
                + messages[1]["content"],
            }
        ] + messages[2:]
    assert all([msg["role"] == "user" for msg in messages[::2]]) and all(
        [msg["role"] == "assistant" for msg in messages[1::2]]
    ), (
        "model only supports 'system', 'user' and 'assistant' roles, "
        "starting with 'system', then 'user' and alternating (u/a/u/a/u...)"
    )
    template = "".join(
        [
            f"<s>{B_INST} {(prompt['content']).strip()} {E_INST} {(answer['content']).strip()} </s>"
            for prompt, answer in zip(
                messages[::2],
                messages[1::2],
            )
        ]
    )
    if messages[-1]["role"] == "assistant":
        template = (
            template[: template.rfind(E_INST)]
            + E_INST
            + f" {(messages[-1]['content'])}"
        )
    else:
        template += f"<s>{B_INST} {(messages[-1]['content']).strip()} {E_INST}"
    template = template[3:]
    return template


if __name__ == "__main__":
    from mxlm import ChatAPI

    c = ChatAPI()
    msgs = c(dict(system="Helpful assistant", user="Repeat Yes"), return_messages=True)
    msgs = c(msgs + [{"role": "user", "content": "Repeat No!!!"}], return_messages=True)

    llama2_chat = messages_to_llama2_chat(msgs[:])
    print(llama2_chat)
