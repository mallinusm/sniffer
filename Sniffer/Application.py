import os

from Sniffer.Capturer import Capturer
from Sniffer.Devices import Devices
from Sniffer.Output.Message import Message
from Sniffer.Selectors.Selectors import Selectors


class Application:
    device = None
    aliases = None
    running = None
    verbose = None
    commands = None
    selectors = None

    def __init__(self) -> None:
        self.running = True
        self.verbose = False
        self.selectors = []
        self.commands = {
            'exit': self.quit,
            'help': self.help,
            'start': self.start,
            'clear': self.clear,
            'devices': self.devices,
            'device': self.set_device,
            'selector': self.set_selector,
            'verbose': self.toggle_verbose,
            'selectors': self.list_selectors,
            'reset selectors': self.reset_selectors
        }
        self.aliases = {
            'q': 'exit',
            'h': 'help',
            'c': 'clear',
            's': 'start',
            'd': 'devices',
            'v': 'verbose'
        }

    def help(self) -> None:
        for key in self.commands.keys():
            alias = [alias for alias, value in self.aliases.items() if value == key]

            Message.info('{0} ({1})'.format(key, alias[0] if len(alias) > 0 else "No alias"))

    def reset_selectors(self) -> None:
        if self.selectors is None or len(self.selectors) < 1:
            Message.info('Selectors already empty.')
        else:
            self.selectors = []

            Message.info('Selectors reset.')

    def set_selector(self) -> None:
        selector = Selectors().choose()

        Message.info('Selected {0}'.format(selector.__name__))

        # Not all targets may need a value. For the moment it is the case, so let's assume we need the input.
        value = None
        while value is None or value is "":
            value = Message.input('<Choose {0}>: '.format(selector().get_name()))

        selector = selector(value)

        self.selectors.append(selector)

        Message.info('Selector {0} ({1}) was added.'.format(selector.get_name(), selector.get_value()))

    def list_selectors(self) -> None:
        if len(self.selectors) < 1:
            Message.info('No selectors specified.')
        else:
            for selector in self.selectors:
                Message.info('{0} with value {1}'.format(selector.get_name(), selector.get_value()))

    def quit(self) -> None:
        self.running = False

    def clear(self) -> None:
        os.system('cls' if os.name == 'nt' else 'clear')

    def devices(self) -> None:
        Devices().list()

    def set_device(self) -> None:
        self.device = Devices().choose()

    def toggle_verbose(self) -> None:
        self.verbose = not self.verbose

        Message.info('Verbose is now {0}'.format('on' if self.verbose else 'off'))

    def start(self) -> None:
        if len(self.selectors) < 1:
            self.set_selector()

        if self.device is None:
            self.set_device()

        Capturer(self.selectors, self.verbose).capture(self.device)

    @staticmethod
    def show_welcome() -> None:
        delimiter = '+{0}+'.format('-' * 28)

        Message.info(delimiter)

        Message.info('|{0}|'.format('sniffer'.upper().center(28, ' ')))

        Message.info(delimiter)

    def main(self) -> None:
        Application.show_welcome()

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
