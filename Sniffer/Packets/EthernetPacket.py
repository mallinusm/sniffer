import socket
from struct import unpack

from Sniffer.Packets import Packet
from Sniffer.Packets.BasePacket import BasePacket


class EthernetPacket(BasePacket):
    header_length = 14

    def __init__(self, packet: Packet):
        BasePacket.__init__(self, {
            'type': None,
            'source_address': None,
            'destination_address': None
        }, packet, self.header_length)

    @staticmethod
    def ethernet_address(address: str):
        return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(address[0]), ord(address[1]), ord(address[2]),
                                                  ord(address[3]), ord(address[4]), ord(address[5]))

    def get_destination_address(self) -> str:
        return self.bag.get_attribute('destination_address')

    def get_source_address(self) -> str:
        return self.bag.get_attribute('source_address')

    def get_type(self) -> int:
        return self.bag.get_attribute('type')

    def decode(self) -> 'EthernetPacket':
        header = unpack('!6s6sH', self.packet.get_payload()[:self.header_length])

        self.bag.set_attribute('destination_address', self.ethernet_address(str(header[0])))
        self.bag.set_attribute('source_address', self.ethernet_address(str(header[1])))
        self.bag.set_attribute('type', socket.ntohs(header[2]))

        return self
