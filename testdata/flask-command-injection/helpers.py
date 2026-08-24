import os


def run_ping(host):
    cmd = f"ping -c 1 {host}"
    os.system(cmd)
    return cmd
