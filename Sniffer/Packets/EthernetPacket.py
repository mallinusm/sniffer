import socket
from struct import unpack

from Sniffer.Packets import Packet


class EthernetPacket:
    packet = None
    payload = None
    type = None
    destination_address = None
    source_address = None
    header_length = 14

    def __init__(self, packet: Packet):
        self.packet = packet

    @staticmethod
    def ethernet_address(address):
        return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(address[0]), ord(address[1]), ord(address[2]),
                                                  ord(address[3]), ord(address[4]), ord(address[5]))

    def get_destination_address(self) -> str:
        return self.destination_address

    def get_source_address(self) -> str:
        return self.source_address

    def get_type(self) -> int:
        return self.type

    def get_payload(self) -> bytes:
        return self.payload

    def decode(self) -> 'EthernetPacket':
        header = unpack('!6s6sH', self.packet.get_payload()[:self.header_length])

        self.destination_address = self.ethernet_address(str(header[0]))
        self.source_address = self.ethernet_address(str(header[1]))
        self.type = socket.ntohs(header[2])
        self.payload = self.packet.get_payload()[self.header_length:]

        return self

    def to_string(self) -> str:
        return 'Source address: {0}, Destination address: {1}, Type: {2}'.format(
            self.get_source_address(), self.get_destination_address(), self.get_type()
        )