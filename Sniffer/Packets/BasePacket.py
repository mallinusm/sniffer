import inspect

from Sniffer.Bag import Bag


class BasePacket:
    bag = None
    offset = None
    packet = None

    def __init__(self, bag: dict, packet: 'BasePacket', offset: int = 0) -> None:
        self.bag = Bag(bag)
        self.packet = packet
        self.offset = offset

    def get_packet(self) -> 'BasePacket':
        return self.packet

    def get_bag(self) -> Bag:
        return self.bag

    def get_payload(self) -> bytes:
        if isinstance(self.offset, int):
            return self.packet.get_payload()[self.offset:]
        else:
            return self.packet.get_payload()

    def to_string(self) -> str:
        # Dirty... There seems to be no other way around.
        return 'Class: {0}: {1}'.format(inspect.stack()[0][0].f_locals['self'].__class__.__name__, self.bag.to_string())
