import datetime
import inspect
import pcapy
from typing import Union

from Sniffer.Identifier import Identifier
from Sniffer.Output.Message import Message
from Sniffer.Packets.BasePacket import BasePacket
from Sniffer.Packets.EthernetPacket import EthernetPacket
from Sniffer.Packets.IPPacket import IPPacket
from Sniffer.Packets.Packet import Packet
from Sniffer.Packets.TCPPacket import TCPPacket
from Sniffer.Targets.Target import Target


class Capturer:
    targets = None
    identifier = None
    verbose = None

    def __init__(self, targets: list, verbose: bool = False):
        self.identifier = Identifier()
        self.targets = targets
        self.verbose = verbose

    def capture(self, device: str) -> None:
        Message.info('Capturing packets on device: {0}'.format(device))

        try:
            capture = pcapy.open_live(device, 65536, 1, 0)

            capture.setfilter('tcp')

            while True:
                (header, packet) = capture.next()

                if self.verbose:
                    Message.info('Class: {0}, Time: {1}'.format(header.__class__.__name__, Capturer.get_timestamp()))

                self.recursive_parse_packet(packet)

                # Remove.
                break
        except (KeyboardInterrupt, SystemExit):
            pass

    @staticmethod
    def get_timestamp() -> str:
        return datetime.datetime.now().strftime('%Y-%m-%d %H:%M')

    @staticmethod
    def is_target(target: Target, packet: BasePacket) -> bool:
        return packet.__class__ is inspect.signature(target.check).parameters['packet'].annotation

    def handle_targets(self, packet):
        for target in self.targets:
            if Capturer.is_target(target, packet) and target.check(packet):
                # Save/Export?
                Message.info('[{0}] Found packet({1}) for target({2}) with value {3}'.format(
                    Capturer.get_timestamp(), packet.__class__.__name__, target.get_name(), target.get_value()
                ))

    def recursive_parse_packet(self, packet: Union[bytes, BasePacket, Packet]):  # Add correct return Tuple.
        if self.verbose:
            if hasattr(packet, 'to_string'):
                Message.info(packet.to_string())
            else:
                Message.info('Type: {0}'.format(type(packet)))

        self.handle_targets(packet)

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
