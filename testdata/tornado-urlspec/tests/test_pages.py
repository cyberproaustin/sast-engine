"""NEGATIVE. A test's handler table is not the application's attack surface.

A Tornado test builds an application of its own out of exactly the same tuples, and a
route that exists only in a test does not exist in the program that is deployed. The
handler this registers is defined in a file that is NOT a test and is registered nowhere
else, so if this table were read as a registration the injection inside it would be
reported against production source.
"""
from handlers.pages import ProbeHandler

default_handlers = [
    (r"/probe", ProbeHandler),
]
