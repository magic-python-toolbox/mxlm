# -*- coding: utf-8 -*-

from .__info__ import __version__, __description__
from .chat_api import ChatAPI
from .chatmd_utils import messages_to_chatmd, chatmd_to_messages
from .mxlm_utils import (
    df_to_html,
    markdown_escape,
    remove_last_assistant,
    remove_system_prompt,
    message_to_sequence,
    messages_to_sequence,
    messages_to_condition_key,
    sanity_check_messages,
    bbcode_to_markdown_math,
    hash_object_sha256_base64,
)
from .random_utils import shuffle_loop_with_seed

# Not imported by default
# from .richtext import *

# for paste json to dict
true = True
false = False
null = None
