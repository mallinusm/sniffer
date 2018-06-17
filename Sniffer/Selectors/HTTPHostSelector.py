from Sniffer.Packets.HTTPPacket import HTTPPacket
from Sniffer.Packets.IPPacket import IPPacket
from Sniffer.Selectors.Selector import Selector


class HTTPHostSelector(Selector):
    def check(self, packet: HTTPPacket) -> bool:
        host = self.get_value()

        # Normally, the HTTP packet is wrapped in a TCP packet, which is wrapped in an IP packet.
        ip_packet = packet.get_packet().get_packet()

        return isinstance(ip_packet, IPPacket) and \
               (host == ip_packet.get_source_address() or host == ip_packet.get_destination_address())

    def get_name(self) -> str:
        return 'HTTP Host'
