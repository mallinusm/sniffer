from Sniffer.Packets.IPPacket import IPPacket
from Sniffer.Selectors.Selector import Selector


class IPAddressSelector(Selector):
    def get_name(self) -> str:
        return 'IP Address'

    def check(self, packet: IPPacket) -> bool:
        ip_address = self.get_value()

        return packet.get_source_address() == ip_address or packet.get_destination_address() == ip_address
