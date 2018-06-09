import abc

from Sniffer.Packets import Packet


class Target(metaclass=abc.ABCMeta):
    value = None

    def __init__(self, value: str = None):
        self.value = value

    def get_value(self) -> str:
        return self.value

    @abc.abstractmethod
    def check(self, packet: Packet) -> bool:
        pass

    @abc.abstractmethod
    def get_name(self) -> str:
        pass
