from Sniffer.Exceptions.NonIdentifiedProtocolException import NonIdentifiedProtocolException
from Sniffer.Packets.BasePacket import BasePacket
from Sniffer.Packets.HTTPPacket import HTTPPacket
from Sniffer.Packets.TCPPacket import TCPPacket


class Identifier:
    protocols = None

    def __init__(self):
        # Add FTP
        self.protocols = {
            8000: HTTPPacket  # Obviously more possible ports for HTTP. 8000 is often used for local development.
        }

    def decode(self, packet: TCPPacket) -> BasePacket:
        for port, protocol in self.protocols.items():
            if packet.get_source_port() == port or packet.get_destination_port() == port:
                return protocol(packet).decode()

        raise NonIdentifiedProtocolException('No protocol identified.')
