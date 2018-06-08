import datetime
import pcapy

from Sniffer.Output.Message import Message
from Sniffer.Packets.EthernetPacket import EthernetPacket
from Sniffer.Packets.IPPacket import IPPacket
from Sniffer.Packets.Packet import Packet
from Sniffer.Packets.TCPPacket import TCPPacket


class Capturer:
    def capture(self, device: str) -> None:
        Message.info('Capturing packets on device: {0}'.format(device))

        try:
            capture = pcapy.open_live(device, 65536, 1, 0)

            # Add more filters (only HTTP and FTP)
            # capture.setfilter('tcp')

            while True:
                (header, packet) = capture.next()

                Message.info('Class: {0}, Time: {1}'.format(
                    header.__class__.__name__, datetime.datetime.now().strftime('%Y-%m-%d %H:%M'))
                )

                self.parse_packet(packet)

                break
        except (KeyboardInterrupt, SystemExit):
            pass

    def parse_packet(self, packet: bytes):
        packet = Packet(packet)

        Message.info(packet.to_string())

        ethernet_packet = EthernetPacket(packet).decode()

        Message.info(ethernet_packet.to_string())

        if ethernet_packet.get_type() == 8:
            ip_packet = IPPacket(ethernet_packet).decode()

            Message.info(ip_packet.to_string())

            if ip_packet.get_protocol() == 6:
                tcp_packet = TCPPacket(ip_packet).decode()

                Message.info(tcp_packet.to_string())
