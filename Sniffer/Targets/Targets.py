from Sniffer.Output.Message import Message
from Sniffer.Targets import Target
from Sniffer.Targets.IPAddressTarget import IPAddressTarget


class Targets:
    targets = None

    def __init__(self):
        # We should be doing this dynamically. Scan all targets within the Sniffer.Targets module.
        self.targets = [
            IPAddressTarget
        ]

    def choose(self) -> Target:
        for i, target in enumerate(self.targets):
            Message.info('{0}: {1}'.format(i, target().get_name()))

        target = self.targets[int(Message.input('<Choose target type>: '))]

        return target
