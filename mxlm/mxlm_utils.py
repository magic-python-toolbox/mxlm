#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Mar 29 16:15:58 2024

@author: yl
"""


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
