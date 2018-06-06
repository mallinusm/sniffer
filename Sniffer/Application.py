import os

from Sniffer.Capturer import Capturer
from Sniffer.Devices import Devices
from Sniffer.Output.Message import Message


class Application:
    commands = None
    aliases = None
    running = None
    device = None

    def __init__(self) -> None:
        self.running = True
        self.commands = {
            'quit': self.quit,
            'exit': self.quit,
            'clear': self.clear,
            'devices': self.devices,
            'device': self.set_device,
            'start': self.start
        }
        self.aliases = {
            's': 'start'
        }

    def quit(self) -> None:
        self.running = False

    def clear(self) -> None:
        os.system('cls' if os.name == 'nt' else 'clear')

    def devices(self) -> None:
        Devices().list()

    def set_device(self) -> None:
        self.device = Devices().choose()

    def start(self) -> None:
        if self.device is None:
            self.set_device()

        Capturer().capture(self.device)

    def main(self) -> None:
        try:
            while self.running:
                command = Message.input()

                if command in self.commands:
                    self.commands.get(command)()
                elif command in self.aliases:
                    self.commands.get(self.aliases.get(command))()
                else:
                    os.system(command)
        except (KeyboardInterrupt, SystemExit):
            pass


if __name__ == '__main__':
    Application().main()
