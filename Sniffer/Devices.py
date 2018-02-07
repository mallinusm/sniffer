import pcapy

from Sniffer.Output.Message import Message


class Devices:
    message = None

    def __init__(self) -> None:
        self.message = Message()

    def list(self) -> None:
        self.message.info(pcapy.findalldevs())

    def choose(self) -> str:
        devices = pcapy.findalldevs()

        for i, device in enumerate(devices):
            self.message.info('{0}: {1}'.format(i, device))

        device = devices[int(self.message.input('<Choose device>: '))]

        self.message.info('Chosen device: {0}'.format(device))

        return device
