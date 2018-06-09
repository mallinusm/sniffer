import datetime
import pcapy

from Sniffer.Identifier import Identifier
from Sniffer.Output.Message import Message
from Sniffer.Packets.EthernetPacket import EthernetPacket
from Sniffer.Packets.IPPacket import IPPacket
from Sniffer.Packets.Packet import Packet
from Sniffer.Packets.TCPPacket import TCPPacket


class Capturer:
    identifier = None
    verbose = None

    def __init__(self, verbose: bool):
        self.identifier = Identifier()
        self.verbose = verbose

    def capture(self, device: str) -> None:
        Message.info('Capturing packets on device: {0}'.format(device))

        try:
            capture = pcapy.open_live(device, 65536, 1, 0)

            capture.setfilter('tcp')

            while True:
                (header, packet) = capture.next()

                """
                Message.info('Class: {0}, Time: {1}'.format(
                    header.__class__.__name__, datetime.datetime.now().strftime('%Y-%m-%d %H:%M'))
                )
                """

                self.parse_packet(packet)

                # break
        except (KeyboardInterrupt, SystemExit):
            pass

    def parse_packet(self, packet: bytes):
        packet = Packet(packet)

        if self.verbose:
            Message.info(packet.to_string())

        ethernet_packet = EthernetPacket(packet).decode()

        if self.verbose:
            Message.info(ethernet_packet.to_string())

        if ethernet_packet.get_type() == 8:
            ip_packet = IPPacket(ethernet_packet).decode()

            if self.verbose:
                Message.info(ip_packet.to_string())

            if ip_packet.get_protocol() == 6:
                tcp_packet = TCPPacket(ip_packet).decode()

                # We are currently only interested in a select number of ports, since we're only parsing HTTP and FTP.
                if tcp_packet.get_destination_port() == 80 and tcp_packet.get_source_port() == 80:
                    Message.info(tcp_packet.to_string())

                    self.identifier.identify_by_port(tcp_packet)
