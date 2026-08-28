"""The views package. Every URLconf above imports from HERE and nothing is defined here.

The same re-export, one node type down. A registration names the class the way it was
imported, and an application of any size imports from the package rather than from the
module the class is written in: all 397 of plane's registrations do, which is why that
application's class-based views resolved to no verbs and produced no entry point at all.
"""
from .orders import RefundView, order_index
from .carts import cart_detail
