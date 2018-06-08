from Sniffer.Bag import Bag


class BasePacket:
    bag = None
    offset = None
    packet = None

    def __init__(self, bag: dict, packet: 'BasePacket', offset: int = 0):
        self.bag = Bag(bag)
        self.packet = packet
        self.offset = offset

    def get_packet(self) -> 'BasePacket':
        return self.packet

    def get_bag(self) -> Bag:
        return self.bag

    def get_payload(self):
        return self.packet.get_payload()[self.offset:]
