#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu May  9 17:08:56 2024

@author: yl
"""


import re


def richtext_to_markdown(text):
    text = re.sub(r"^(\d\d?)\.([^\s])", r"\1. \2", text, flags=re.MULTILINE)
    text = re.sub(r"^(\d\d?)、\s*([^\s])", r"\1. \2", text, flags=re.MULTILINE)
    text = re.sub(r"^-([^\s])", r"- \1", text, flags=re.MULTILINE)
    return text


def recovery_copyed_richtext_to_markdown(text):
    text = re.sub(
        r"^(   ? ?)([^\s]{2,})", rf"[RECOVERY_MD_INDEX_TAG]\2", text, flags=re.MULTILINE
    )
    for idx in range(1, text.count("[RECOVERY_MD_INDEX_TAG]") + 1):
        text = text.replace("[RECOVERY_MD_INDEX_TAG]", f"{idx}. ", 1)
    return text


if __name__ == "__main__":
    print(
        richtext_to_markdown(
            """1.xxxxxx
2.xxxx
3.xxxx
13.xx 5.xx
14. yyyy

-xxxxx
- yyyyyyy

6、xxxx
7、 xxxx"""
        )
    )

    print(
        recovery_copyed_richtext_to_markdown(
            """
  yyyyy
    yyyyy
    yyyyy
     xxxx
     """
        )
    )
