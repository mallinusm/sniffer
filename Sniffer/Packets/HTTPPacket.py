from Sniffer.Packets.BasePacket import BasePacket
from Sniffer.Packets.TCPPacket import TCPPacket


class HTTPPacket(BasePacket):
    def __init__(self, packet: TCPPacket) -> None:
        BasePacket.__init__(self, {}, packet, 0)

    def decode(self) -> 'HTTPPacket':
        payload = str(self.packet.get_payload(), 'utf-8')

        if '\x00' not in payload and len(payload) > 0:
            print(payload)
            print(len(payload))

        # Parse using a HTTP lib

        return self
