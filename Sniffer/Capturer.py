import datetime
import pcapy

from Sniffer.Output.Message import Message
from Sniffer.Packets.EthernetPacket import EthernetPacket
from Sniffer.Packets.Packet import Packet


class Capturer:
    def capture(self, device: str) -> None:
        Message.info('Capturing packets on device: {0}'.format(device))

        try:
            capture = pcapy.open_live(device, 65536, 1, 0)

            # Add more filters (only HTTP and FTP)
            # capture.setfilter('tcp')

            while True:
                (header, packet) = capture.next()

                self.parse_packet(packet)

                break
        except (KeyboardInterrupt, SystemExit):
            pass

    def parse_packet(self, packet: bytes):
        packet = Packet(packet)

        Message.info('Date: {0}, Class {1}, Payload Length: {2}'.format(
            datetime.datetime.now(), type(packet), packet.get_payload_length())
        )

        ethernet_packet = EthernetPacket(packet).decode()

        Message.info(ethernet_packet.to_string())

        if ethernet_packet.get_type() == 8:
            Message.info('It is IP!')
