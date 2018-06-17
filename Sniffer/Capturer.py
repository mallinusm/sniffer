import inspect
import pcapy
from typing import Union

from Sniffer.Exceptions.NonIdentifiedProtocolException import NonIdentifiedProtocolException
from Sniffer.Helpers import Helpers
from Sniffer.Identifier import Identifier
from Sniffer.Output.Message import Message
from Sniffer.Packets.BasePacket import BasePacket
from Sniffer.Packets.EthernetPacket import EthernetPacket
from Sniffer.Packets.IPPacket import IPPacket
from Sniffer.Packets.Packet import Packet
from Sniffer.Packets.TCPPacket import TCPPacket
from Sniffer.Selectors.Selector import Selector


class Capturer:
    verbose = None
    selectors = None
    identifier = None

    def __init__(self, selectors: list, verbose: bool = False):
        self.identifier = Identifier()
        self.selectors = selectors
        self.verbose = verbose

    def capture(self, device: str) -> None:
        Message.info('Capturing packets on device: {0}'.format(device))

        try:
            capture = pcapy.open_live(device, 65536, 1, 0)

            capture.setfilter('tcp')  # We are only interested in TCP packets for this PoC.

            while True:
                (header, packet) = capture.next()

                if self.verbose:
                    Message.info('Class: {0}, Time: {1}'.format(header.__class__.__name__, Helpers.get_timestamp()))

                self.recursive_parse_packet(packet)

                # Remove.
                # break
        except (KeyboardInterrupt, SystemExit):
            pass

    @staticmethod
    def is_selector(selector: Selector, packet: BasePacket) -> bool:
        return packet.__class__ is inspect.signature(selector.check).parameters['packet'].annotation

    def run_selectors(self, packet) -> None:
        for selector in self.selectors:
            if Capturer.is_selector(selector, packet) and selector.check(packet):
                # Save/Export?
                Message.info('[{0}] Found packet({1}) for selector({2}) with value {3}'.format(
                    Helpers.get_timestamp(), packet.__class__.__name__, selector.get_name(), selector.get_value()
                ))

    def recursive_parse_packet(self, packet: Union[bytes, BasePacket, Packet]):  # Add correct return Tuple.
        if self.verbose:
            if hasattr(packet, 'to_string'):
                Message.info(packet.to_string())
            else:
                Message.info('Type: {0}'.format(type(packet)))

        self.run_selectors(packet)

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
        elif isinstance(packet, TCPPacket):
            try:
                packet = self.identifier.decode(packet)

                # More...
            except NonIdentifiedProtocolException:
                pass
