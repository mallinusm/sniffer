class TCPSession:
    packets = None
    port_numbers = None
    sequence_numbers = None
    source_ip_address = None
    destination_ip_address = None

    """
    TCP streams are identified by the combination of:
    - Source IP address
    - Destination IP address
    - TCP port numbers (both source and destination)
    - Sequence numbers

    Source: https://www.wireshark.org/lists/wireshark-users/201105/msg00045.html
    """
    def __init__(self):
        pass
