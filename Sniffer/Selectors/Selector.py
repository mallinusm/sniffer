import abc

from Sniffer.Packets.BasePacket import BasePacket


class Selector(metaclass=abc.ABCMeta):
    value = None

    def __init__(self, value: str = None) -> None:
        self.value = value

    def get_value(self) -> str:
        return self.value

    @abc.abstractmethod
    def check(self, packet: BasePacket) -> bool:
        pass

    @abc.abstractmethod
    def get_name(self) -> str:
        pass
