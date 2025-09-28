from copy import deepcopy

prompt_logprobs_request_kwargs = dict(
    max_tokens=1,
    temperature=1.0,
    top_p=1.0,
    logprobs=True,
    # top_logprobs=1,
    stream=False,
    extra_body=dict(
        prompt_logprobs=True,
        add_generation_prompt=True,  # need <|stop|> token logprob for last message
        continue_final_message=False,
        skip_special_tokens=False,
    ),
)


def compute_prefill_logprobs(chat, msgs):
    """
    1. using vLLM prompt_logprobs=True to get msgs's prompt logprobs of the mxlm.ChatAPI model
    2. Convert vLLM prompt_logprob format to top_logprobs format (named `prefill_logprobs`)
    3. Align prefill_logprobs to each message base on its content, and set to msg["prefill_logprobs"]
    """
    response = chat(msgs, return_dict=True, **prompt_logprobs_request_kwargs)
    prefill_logprobs = [
        standardization_prompt_logprob(d) for d in response["prompt_logprobs"] if d
    ]
    msgs_with_prompt_logprobs = align_prefill_logprobs_to_messages(
        prefill_logprobs, msgs
    )
    return msgs_with_prompt_logprobs


def standardization_prompt_logprob(prompt_logprob):
    """
    Convert vLLM prompt_logprob format to top_logprobs format
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


def prefill_logprobs_to_sequence(prefill_logprobs):
    return "".join([t["token"] for t in prefill_logprobs if t])


def align_prefill_logprobs_to_messages(prefill_logprobs, messages):
    """
    If content is only a word like `assistant` or `user`, may case mis-align to role name
    """
    sequence = prefill_logprobs_to_sequence(prefill_logprobs)
    unicode_idx_to_token_idx = []
    for idx, token in enumerate(prefill_logprobs):
        unicode_idx_to_token_idx += [idx] * len(token["token"])
    sequence_remain = sequence[:]
    # using inverse order, because the newer msg is more important
    for msg in messages[::-1]:
        content = msg["content"]
        if content == "":
            continue
        if isinstance(content, str):
            start_unicode_idx = sequence_remain.rfind(content)
            assert start_unicode_idx >= 0, f"Should '{content}' in '{sequence_remain}'"
            start_token_idx = unicode_idx_to_token_idx[start_unicode_idx]
            end_unicode_idx = (
                start_unicode_idx + len(content) + 1
            )  # plus 1 for <|stop|> token
            end_token_idx = unicode_idx_to_token_idx[end_unicode_idx]
            msg["prefill_logprobs"] = prefill_logprobs[
                start_token_idx : end_token_idx + 1
            ]
            sequence_remain = sequence_remain[:start_unicode_idx]
        elif isinstance(content, list):
            for reverse_idx, chunk in enumerate(content[::-1]):
                if chunk["type"] == "text":
                    start_unicode_idx = sequence_remain.rfind(chunk["text"])
                    assert (
                        start_unicode_idx >= 0
                    ), f"Should '{chunk['text']}' in '{sequence_remain}'"
                    start_token_idx = unicode_idx_to_token_idx[start_unicode_idx]
                    end_unicode_idx = start_unicode_idx + len(chunk["text"])
                    # plus 1 for <|stop|> token if is last chunk
                    if reverse_idx == 0:
                        end_unicode_idx += 1
                    end_token_idx = unicode_idx_to_token_idx[end_unicode_idx]
                    chunk["prefill_logprobs"] = prefill_logprobs[
                        start_token_idx : end_token_idx + 1
                    ]
                    sequence_remain = sequence_remain[:start_unicode_idx]
    return messages


if __name__ == "__main__":
    from boxx import *
    from mxlm import ChatAPI

    chat = ChatAPI.free_api()

    msgs = [
        # {"role": "system", "content": ""},
        {"role": "user", "content": "5+7=?"},
        # {"role": "user","content": [{"type": "text", "text": "5+7"},{"type": "text", "text": "=?"},],},  # test chunk content
        {"role": "assistant", "content": "32"},
        # {"role": "assistant", "content": "12"},
        # {"role": "assistant", "content": "prefix 🥢subfix"},  # test tokenizer
    ]
    msgs_with_prefill_logprobs = compute_prefill_logprobs(chat, msgs)
    tree(msgs_with_prefill_logprobs)
