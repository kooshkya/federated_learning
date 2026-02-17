import sys
from scapy.all import get_if_list


def get_if() -> str:
    """Get the network interface name (assumes 'eth0' for Mininet)."""
    for iface_name in get_if_list():
        if "eth0" in iface_name:
            return iface_name
    print("Cannot find eth0 interface", file=sys.stderr)
    exit(1)
