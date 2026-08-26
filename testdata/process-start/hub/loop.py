"""An event loop, standing in for the one a real application borrows from its framework."""


def run_sync(fn):
    return fn()
