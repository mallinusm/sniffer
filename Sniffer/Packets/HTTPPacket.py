from Sniffer.Exceptions.InvalidPayloadException import InvalidPayloadException
from Sniffer.Helpers import Helpers
from Sniffer.Packets.BasePacket import BasePacket
from Sniffer.Packets.TCPPacket import TCPPacket


class HTTPPacket(BasePacket):
    def __init__(self, packet: TCPPacket) -> None:
        BasePacket.__init__(self, {}, packet, 0)

    def decode(self) -> 'HTTPPacket':
        # Parse HTTP data using a lib (headers, status code, ...).
        http_payload = str(self.packet.get_payload(), 'utf-8')

        if '\x00' in http_payload or len(http_payload) < 1:
            raise InvalidPayloadException('Invalid HTTP payload.')

        return self

    def export(self) -> None:
        Helpers.write_all_lines(str(self.packet.get_payload(), 'utf-8'))
