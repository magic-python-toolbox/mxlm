from copy import deepcopy

prompt_logprobs_kwargs = dict(
    return_dict=True,
    max_tokens=1,
    temperature=1.0,
    top_p=1.0,
    logprobs=True,
    # top_logprobs=1,
    stream=False,
    extra_body=dict(
        prompt_logprobs=True,
        add_generation_prompt=True,
        continue_final_message=False,
        skip_special_tokens=False,
    ),
)


def compute_prompt_logprobs(chat, msgs):
    response = chat(msgs, **prompt_logprobs_kwargs)
    response["prefill_logprobs"] = [
        standardization_prompt_logprob(d) for d in response["prompt_logprobs"] if d
    ]
    return response


def standardization_prompt_logprob(prompt_logprob):
    """
    prompt_logprob example
    {'5743': {'logprob': -11.900545120239258,
       'rank': 1265,
       'decoded_token': 'fix'},
      '7660': {'logprob': -0.6036703586578369,
       'rank': 1,
       'decoded_token': 'stitute'}}
    """

    if not prompt_logprob:
        return {}
    group_entries = []
    for token_id, info in prompt_logprob.items():
        token_text = info.get("decoded_token") or ""
        token_bytes = info.get("bytes")
        entry = {
            "token": token_text,
            "logprob": info["logprob"],
            "token_id": token_id,
        }
        if token_bytes is not None:
            entry["bytes"] = token_bytes
        if info.get("rank") is not None:
            entry["rank"] = info.get("rank")
        # Preserve any extra metadata provided by the API without overriding
        for k, v in info.items():
            if k in {"decoded_token", "logprob", "rank", "bytes"}:
                continue
            entry.setdefault(k, v)
        group_entries.append(entry)
    primary_entry = deepcopy(group_entries[0])
    primary_entry["top_logprobs"] = ([dict(entry) for entry in group_entries],)
    return primary_entry


def prefill_logprobs_to_sequence(prompt_logprobs):
    return "".join([t["token"] for t in prefill_logprobs if t])


def align_prefill_logprobs_to_messages(prefill_logprobs, messages):
    sequence = prefill_logprobs_to_sequence(prefill_logprobs)

    sequence_left = sequence[:]
    for msg in messages:
        content = msg["content"]
        if content == "":
            continue
        if isinstance(content, str):
            sequence_left.rfind(content)
        elif isinstance(content, list):
            for chunk in content[::-1]:
                if chunk["type"] == "text":
                    chunk["text"]


if __name__ == "__main__":
    from mxlm import ChatAPI
    import json

    prompt_logprobs = {  # token id: dict
        "5743": {"logprob": -11.900545120239258, "rank": 1265, "decoded_token": "fix"},
        "7660": {"logprob": -0.6036703586578369, "rank": 1, "decoded_token": "stitute"},
    }
    demo_top_logprobs = standardization_prompt_logprob(prompt_logprobs)
    print(json.dumps(demo_top_logprobs, ensure_ascii=False, indent=2))

    chat = ChatAPI.free_api()

    msgs = [
        {"role": "system", "content": ""},
        {"role": "user", "content": "5+6="},
        # {"role": "assistant", "content": "21"},
        # {"role": "assistant", "content": "11"},
        {"role": "assistant", "content": "prefix 🥢subfix"},
    ]
    response = compute_prompt_logprobs(chat, msgs)
    prefill_logprobs = response["prefill_logprobs"]

    seqence = prefill_logprobs_to_sequence(prefill_logprobs)

    msgs_with_prompt_logprobs = align_prefill_logprobs_to_messages(
        prefill_logprobs, msgs
    )
    print(seqence)
