"""What a call written UNDER a property read used to contribute: nothing at all.

`helper(request).name` is one expression with a call inside it, and the frontend visited
the base of a property read only when the base was a plain name. Everything else returned
early -- so this shape recorded no property, no symbol, and no CALL. Not an unresolved
edge, which at least says something was there; an absent node. Wherever a program reads a
field off the result of a call the call graph simply had a hole, and in a codebase whose
data layer answers in objects that is most of it.

Three wrappers rather than one, and the duplication is the point: taint is
context-insensitive, so a helper called from both a caller-fed route and a literal one
carries the union of the two and the negative would prove nothing.
"""
import os


class Parsed:
    def __init__(self, value):
        self.value = value


def run_and_wrap(raw):
    # The shell is HERE, one call below the property read that used to hide the call.
    # Nothing in the handler reaches it unless the call was recorded at all.
    os.system(f"ping -c 1 {raw}")
    return Parsed(raw)


def wrap(raw):
    return Parsed(raw)


def wrap_literal(raw):
    return Parsed(raw)
