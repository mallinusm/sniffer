from Sniffer.Exceptions.InvalidPayloadException import InvalidPayloadException
from Sniffer.Helpers import Helpers
from Sniffer.Packets.BasePacket import BasePacket
from Sniffer.Packets.TCPPacket import TCPPacket


class FTPPacket(BasePacket):
    def __init__(self, packet: TCPPacket):
        BasePacket.__init__(self, {}, packet)

    def decode(self) -> 'FTPPacket':
        ftp_payload = Helpers.bytes_to_utf8(self.packet.get_payload())

        # Basic heuristic techniques, might not be accurate.
        if '\x00' in ftp_payload or len(ftp_payload) < 1:
            raise InvalidPayloadException('Invalid FTP payload.')

        return self
