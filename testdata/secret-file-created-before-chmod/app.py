"""One private file lifecycle and four spellings that are not it.

The positive is JupyterHub's order: create at the process umask, write the secret, then
chmod the same path to 0600.  The chmod is not a repair for the interval before it.  Each
negative removes one fact from that three-line proof: mode at creation, a safe temporary
file constructor, chmod before creation, or no secret write through the handle.
"""
import os
import tempfile


def unsafe_secret_file(path, secret):
    # POSITIVE. The later private mode says what kind of file this was intended to be;
    # between open and chmod it exists with whatever access the process umask permits.
    with open(path, "w") as handle:
        handle.write(secret)
    os.chmod(path, 0o600)


def explicit_opener(path, secret):
    # NEGATIVE. The opener creates the descriptor with private bits from the start.
    opener = lambda name, flags: os.open(name, flags, 0o600)
    with open(path, "w", opener=opener) as handle:
        handle.write(secret)
    os.chmod(path, 0o600)


def descriptor_mode(path, secret):
    # NEGATIVE. os.open receives the mode as part of the atomic creation operation.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(secret)


def named_temporary(secret):
    # NEGATIVE. NamedTemporaryFile creates its private descriptor before exposing it.
    with tempfile.NamedTemporaryFile(mode="w") as handle:
        handle.write(secret)


def restricted_before_open(path, secret):
    # NEGATIVE. Odd but not this ordering defect: restriction precedes this open.
    os.chmod(path, 0o600)
    with open(path, "w") as handle:
        handle.write(secret)


def empty_private_file(path):
    # NEGATIVE. No value is written through this handle, so the three-event lifecycle
    # that makes the positive precise is absent.
    with open(path, "w"):
        pass
    os.chmod(path, 0o600)


if __name__ == "__main__":
    unsafe_secret_file("unsafe.key", "generated-cookie-secret")
    explicit_opener("opener.key", "generated-cookie-secret")
    descriptor_mode("descriptor.key", "generated-cookie-secret")
    named_temporary("generated-cookie-secret")
    restricted_before_open("existing.key", "generated-cookie-secret")
    empty_private_file("empty.key")
