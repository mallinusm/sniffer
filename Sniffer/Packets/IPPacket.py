import socket
from struct import unpack

from Sniffer.Packets import EthernetPacket


class IPPacket:
    ihl = None
    ttl = None
    packet = None
    offset = None
    length = None
    payload = None
    version = None
    protocol = None
    checksum = None
    header_length = 20
    identification = None
    source_address = None
    type_of_service = None
    destination_address = None

    def __init__(self, packet: EthernetPacket):
        self.packet = packet

    def get_version(self) -> int:
        return self.version

    def get_ihl(self) -> int:
        return self.ihl

    def get_type_of_service(self) -> int:
        return self.type_of_service

    def get_identification(self) -> int:
        return self.identification

    def get_offset(self) -> int:
        return self.offset

    def get_ttl(self) -> int:
        return self.ttl

    def get_protocol(self) -> int:
        return self.protocol

    def get_checksum(self) -> int:
        return self.checksum

    def get_source_address(self) -> str:
        return self.source_address

    def get_destination_address(self) -> str:
        return self.destination_address

    def decode(self) -> 'IPPacket':
        ip_header = unpack('!BBHHHBBH4s4s', self.packet.get_payload()[:self.header_length])

        self.version = ip_header[0] >> 4
        self.ihl = ip_header[0] & 0xF
        self.type_of_service = ip_header[1]
        self.length = ip_header[2]
        self.identification = ip_header[3]

        # Not completely accurate. The 0, DF and MF are not taken into consideration (out of scope for this project).
        self.offset = ip_header[4]

        self.ttl = ip_header[5]
        self.protocol = ip_header[6]
        self.checksum = ip_header[7]
        self.source_address = socket.inet_ntoa(ip_header[8])
        self.destination_address = socket.inet_ntoa(ip_header[9])

        # Since an IPv4 header may contain a variable number of options, the IHL (Internet Header Length) field
        # specifies the size of the header (this also coincides with the offset to the data). The minimum value for this
        # field is 5, which indicates a length of 5 * 32 bits = 160 bits = 20 bytes. As a 4-bit field, the maximum value
        # is 15 words (15 * 32 bits, or 480 bits = 60 bytes).
        self.payload = self.packet.get_payload()[self.ihl * 4:]

        return self

    def to_string(self) -> str:
        return 'Class: {0}, Version: {1}, IHL: {2}, QoS: {3}, Length: {4}, Identification: {5}, TTL: {6}, ' \
               'Protocol: {7}, Checksum: {8}, Source address: {9}, Destination address: {10}'.format(
            self.__class__.__name__, self.get_version(), self.get_ihl(), self.get_type_of_service(), self.length,
            self.get_identification(), self.get_ttl(), self.get_protocol(), self.get_checksum(),
            self.get_source_address(), self.get_destination_address()
        )
