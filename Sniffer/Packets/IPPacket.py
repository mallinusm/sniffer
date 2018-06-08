import socket
from struct import unpack

from Sniffer.Packets import EthernetPacket
from Sniffer.Packets.BasePacket import BasePacket


class IPPacket(BasePacket):
    header_length = 20

    def __init__(self, packet: EthernetPacket):
        BasePacket.__init__(self, {
            'ihl': None,
            'ttl': None,
            'offset': None,
            'length': None,
            'version': None,
            'protocol': None,
            'checksum': None,
            'identification': None,
            'source_address': None,
            'type_of_service': None,
            'destination_address': None
        }, packet, self.header_length)

    def get_version(self) -> int:
        return self.bag.get_attribute('version')

    def get_ihl(self) -> int:
        return self.bag.get_attribute('ihl')

    def get_type_of_service(self) -> int:
        return self.bag.get_attribute('type_of_service')

    def get_length(self) -> int:
        return self.bag.get_attribute('length')

    def get_identification(self) -> int:
        return self.bag.get_attribute('identification')

    def get_offset(self) -> int:
        return self.bag.get_attribute('offset')

    def get_ttl(self) -> int:
        return self.bag.get_attribute('ttl')

    def get_protocol(self) -> int:
        return self.bag.get_attribute('protocol')

    def get_checksum(self) -> int:
        return self.bag.get_attribute('checksum')

    def get_source_address(self) -> str:
        return self.bag.get_attribute('source_address')

    def get_destination_address(self) -> str:
        return self.bag.get_attribute('destination_address')

    def decode(self) -> 'IPPacket':
        ip_header = unpack('!BBHHHBBH4s4s', self.packet.get_payload()[:self.header_length])

        self.bag.set_attribute('version', ip_header[0] >> 4)
        self.bag.set_attribute('ihl', ip_header[0] & 0xF)
        self.bag.set_attribute('type_of_service', ip_header[1])
        self.bag.set_attribute('length', ip_header[2])
        self.bag.set_attribute('identification', ip_header[3])

        # Not completely accurate. The 0, DF and MF are not taken into consideration (out of scope for this project).
        self.bag.set_attribute('offset', ip_header[4])

        self.bag.set_attribute('ttl', ip_header[5])
        self.bag.set_attribute('protocol', ip_header[6])
        self.bag.set_attribute('checksum', ip_header[7])
        self.bag.set_attribute('source_address', socket.inet_ntoa(ip_header[8]))
        self.bag.set_attribute('destination_address', socket.inet_ntoa(ip_header[9]))

        # Since an IPv4 header may contain a variable number of options, the IHL (Internet Header Length) field
        # specifies the size of the header (this also coincides with the offset to the data). The minimum value for this
        # field is 5, which indicates a length of 5 * 32 bits = 160 bits = 20 bytes. As a 4-bit field, the maximum value
        # is 15 words (15 * 32 bits, or 480 bits = 60 bytes).
        # By default, we expect the header length to be 20 bytes. If that is not the case, we set the calculated offset.
        calculated_offset = self.get_ihl() * 4
        if calculated_offset is not self.header_length:
            self.offset = calculated_offset

        return self
