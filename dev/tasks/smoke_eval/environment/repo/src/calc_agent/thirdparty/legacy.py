"""Vendored code the task excludes from scanning (metadata.excluded_paths).

It has its own eval() so that a broken exclude shows up as a false positive.
"""


def legacy_eval(text):
    return eval(text)
