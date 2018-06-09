import pcapy

from Sniffer.Output.Message import Message


class Devices:
    def __init__(self) -> None:
        pass

    @staticmethod
    def list() -> None:
        Message.info(pcapy.findalldevs())

    @staticmethod
    def choose() -> str:
        devices = pcapy.findalldevs()

        for i, device in enumerate(devices):
            Message.info('{0}: {1}'.format(i, device))

        device = devices[int(Message.input('<Choose device>: '))]

        Message.info('Chosen device: {0}'.format(device))

        return device
