from Sniffer.Output.Message import Message


class Capturer:
    message = None

    def __init__(self) -> None:
        self.message = Message()

    def start(self) -> None:
        self.message.info('Starting...')
