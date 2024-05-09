#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu May  9 17:22:36 2024

@author: yl
"""
import random


def shuffle_loop_with_seed(choices, idx=0, seed=""):
    """
    随机从 choices 中选择，并尽可能保证多样化（均匀、避免重复），通过 seed 和 idx 可复现
    """
    div, mod = divmod(idx, len(choices))
    random.seed(str(seed) + str(div))
    choices_ = list(choices[:])
    random.shuffle(choices_)
    return choices_[mod]
