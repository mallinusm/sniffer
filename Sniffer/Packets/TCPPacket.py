from struct import unpack

from Sniffer.Packets import IPPacket
from Sniffer.Packets.BasePacket import BasePacket


class TCPPacket(BasePacket):
    header_length = 20

    def __init__(self, packet: IPPacket) -> None:
        BasePacket.__init__(self, {
            'flags': None,
            'window': None,
            'offset': None,
            'checksum': None,
            'source_port': None,
            'urgent_pointer': None,
            'sequence_number': None,
            'destination_port': None,
            'acknowledgement_number': None
        }, packet, self.header_length)

    def get_source_port(self) -> int:
        return self.bag.get_attribute('source_port')

    def get_destination_port(self) -> int:
        return self.bag.get_attribute('destination_port')

    def get_sequence_number(self) -> int:
        return self.bag.get_attribute('sequence_number')

    def get_acknowledgement_number(self) -> int:
        return self.bag.get_attribute('acknowledgement_number')

    def get_offset(self) -> int:
        return self.bag.get_attribute('offset')

    def get_flags(self) -> int:
        return self.bag.get_attribute('flags')

    def get_window(self) -> int:
        return self.bag.get_attribute('window')

    def get_checksum(self) -> int:
        return self.bag.get_attribute('checksum')

    def get_urgent_pointer(self) -> int:
        return self.bag.get_attribute('urgent_pointer')

    def decode(self) -> 'TCPPacket':
        tcp_header = unpack('!HHLLBBHHH', self.packet.get_payload()[:self.header_length])

        self.bag.set_attribute('source_port', tcp_header[0])
        self.bag.set_attribute('destination_port', tcp_header[1])
        self.bag.set_attribute('sequence_number', tcp_header[2])
        self.bag.set_attribute('acknowledgement_number', tcp_header[3])
        self.bag.set_attribute('offset', tcp_header[4])
        self.bag.set_attribute('flags', tcp_header[5])
        self.bag.set_attribute('window', tcp_header[6])
        self.bag.set_attribute('checksum', tcp_header[7])
        self.bag.set_attribute('urgent_pointer', tcp_header[8])

        # The data offset field stores the total size of a TCP header in multiples of four bytes.
        calculated_offset = int(self.get_offset() / 4)
        if calculated_offset is not self.header_length:
            self.offset = calculated_offset

        return self
