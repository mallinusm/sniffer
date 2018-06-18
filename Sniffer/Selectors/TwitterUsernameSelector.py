from Sniffer.Helpers import Helpers
from Sniffer.Packets.HTTPPacket import HTTPPacket
from Sniffer.Selectors.Selector import Selector


class TwitterUsernameSelector(Selector):
    def check(self, packet: HTTPPacket) -> bool:
        # Not entirely correct. Since we're testing against local a web server, we don't mind about the domain.
        return self.get_value() in Helpers.bytes_to_utf8(packet.get_payload())

    def get_name(self) -> str:
        return 'Twitter username'
