"""Every way Python fills a method's parameter zero, and every way it does not.

The receiver is declared as the first parameter and, for three of the four shapes below,
no call site writes it -- so an argument a caller wrote at position N arrives at position
N+1. Nothing recorded that, and the damage was not a lost finding: saleor's tokenCreate
came out reporting a cache key built from the client IP as "a record chosen by the
caller's email", because `cls.get_user(info, email, password)` bound `email` onto `info`
and the engine then followed `info.context` as if it were the caller's address.

Each method puts a shell one place away from the other parameter, so the two directions
of the error are separable. In a POSITIVE method the shell is on the parameter the route
writes the caller's value into, and binding one place off sends that value to `safe`
instead -- the finding vanishes. In a NEGATIVE method the shell is on the parameter the
same shift would move the caller's value ONTO, so a corpus with only positives would pass
with the parameters merely shuffled.

Every method has exactly one caller. Taint is context-insensitive, so a method called from
both a safe route and a dangerous one would carry the union of the two and prove nothing.
"""
import os


class Runner:
    @classmethod
    def as_class_method(cls, safe, danger):
        # A classmethod is bound to the class whether it is reached through the class or
        # through an instance, so `cls` is filled by the call and written by nobody.
        os.system(f"ping -c 1 {danger}")
        return safe

    @classmethod
    def as_class_method_negative(cls, danger, safe):
        os.system(f"ping -c 1 {danger}")
        return safe

    @staticmethod
    def as_static_method(safe, danger):
        # `@staticmethod` removes the slot entirely: what is written first IS parameter
        # zero, exactly as for a module-level function.
        os.system(f"ping -c 1 {danger}")
        return safe

    @staticmethod
    def as_static_method_negative(safe, danger):
        os.system(f"ping -c 1 {danger}")
        return safe

    def direct_instance(self, safe, danger):
        # Reached as `Runner.direct_instance(runner, ...)`: through the CLASS an ordinary
        # method is unbound, so the receiver is the first argument the call writes and
        # nothing shifts.
        os.system(f"ping -c 1 {danger}")
        return safe

    def direct_instance_negative(self, safe, danger):
        os.system(f"ping -c 1 {danger}")
        return safe

    def as_instance_method(self, safe, danger):
        os.system(f"ping -c 1 {danger}")
        return safe

    def as_instance_method_negative(self, danger, safe):
        os.system(f"ping -c 1 {danger}")
        return safe

    def relay(self, safe, danger):
        # An IMPLICIT receiver, one frame below an explicit one. Both bindings have to be
        # right for the caller's value to arrive on `danger` here.
        return self.as_instance_method(safe, danger)

    def relay_negative(self, safe, danger):
        return self.as_instance_method_negative(safe, danger)
