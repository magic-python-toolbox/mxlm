#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Mar 29 16:15:58 2024

@author: yl
"""


def df_to_html(df, *args, max_width=400, **argkws):
    """
    Pretty print DataFrame to html
    """
    argkws.setdefault(
        "formatters",
        {
            col: lambda x: f'<div style="max-width:{max_width}px;"><span style="white-space: pre-wrap; font-family: Monospace;">%s</span></div>'
            % x
            for col in df.columns
        },
    )
    argkws.setdefault("escape", False)
    return df.to_html(*args, **argkws)
