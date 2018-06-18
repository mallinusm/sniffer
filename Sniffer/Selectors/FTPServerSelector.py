from Sniffer.Packets.FTPPacket import FTPPacket
from Sniffer.Packets.IPPacket import IPPacket
from Sniffer.Selectors.Selector import Selector


class FTPServerSelector(Selector):
    def check(self, packet: FTPPacket) -> bool:
        server = self.get_value()

        ip_packet = packet.get_packet().get_packet()

        return isinstance(ip_packet, IPPacket) and \
               (server == ip_packet.get_source_address() or server == ip_packet.get_destination_address())

    def get_name(self) -> str:
        return 'FTP Server'
