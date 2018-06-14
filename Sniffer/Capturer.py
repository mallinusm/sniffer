import datetime
import pcapy
from typing import Union

from Sniffer.Identifier import Identifier
from Sniffer.Output.Message import Message
from Sniffer.Packets.BasePacket import BasePacket
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

                if self.verbose:
                    Message.info('Class: {0}, Time: {1}'.format(
                        header.__class__.__name__, datetime.datetime.now().strftime('%Y-%m-%d %H:%M'))
                    )

                self.recursive_parse_packet(packet)

                # Remove.
                break
        except (KeyboardInterrupt, SystemExit):
            pass

    def recursive_parse_packet(self, packet: Union[bytes, BasePacket, Packet]):
        if hasattr(packet, 'to_string'):
            Message.info(packet.to_string())
        else:
            Message.info('Type: {0}'.format(type(packet)))

        # Check for targets here

        if isinstance(packet, bytes):
            return self.recursive_parse_packet(Packet(packet))
        elif isinstance(packet, Packet):
            return self.recursive_parse_packet(EthernetPacket(packet).decode())
        elif isinstance(packet, EthernetPacket):
            # We are only interested in IP packets.
            if packet.get_type() == 8:
                return self.recursive_parse_packet(IPPacket(packet).decode())
        elif isinstance(packet, IPPacket):
            # We are only interested in TCP packets.
            if packet.get_protocol() == 6:
                return self.recursive_parse_packet(TCPPacket(packet).decode())
