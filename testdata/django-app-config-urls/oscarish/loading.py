"""The dynamic class loader every config in this program resolves its views through.

The module label is resolved against a search path at run time -- an installed override
app first, the core app second -- so the MODULE half of the call is genuinely not
decidable from the source. The class NAME is, and it is the half the routes are built
from.
"""
from importlib import import_module


def get_class(module_label, classname, module_prefix="shop"):
    module = import_module(f"{module_prefix}.{module_label}")
    return getattr(module, classname)
