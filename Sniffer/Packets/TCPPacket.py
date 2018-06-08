from Sniffer.Packets import IPPacket


class TCPPacket:
    packet = None

    def __init__(self, packet: IPPacket):
        self.packet = packet

    def decode(self) -> 'TCPPacket':
        return self

    def to_string(self) -> str:
        return ''
