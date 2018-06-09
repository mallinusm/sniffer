from Sniffer.Packets import TCPPacket


class Identifier:
    protocols = None

    def __init__(self):
        self.protocols = {
            80: ''
        }

    def identify_by_port(self, packet: TCPPacket):
        print('trying to identify')
        pass
