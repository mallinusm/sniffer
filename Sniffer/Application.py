import os

from Sniffer.Capturer import Capturer
from Sniffer.Devices import Devices
from Sniffer.Output.Message import Message
from Sniffer.Targets.Targets import Targets


class Application:
    device = None
    targets = None
    aliases = None
    running = None
    verbose = None
    commands = None

    def __init__(self) -> None:
        self.running = True
        self.verbose = False
        self.targets = []
        self.commands = {
            'quit': self.quit,
            'exit': self.quit,
            'start': self.start,
            'clear': self.clear,
            'devices': self.devices,
            'target': self.set_target,
            'device': self.set_device,
            'targets': self.list_targets,
            'verbose': self.toggle_verbose
        }
        self.aliases = {
            'c': 'clear',
            's': 'start',
            't': 'target',
            'd': 'devices',
            'v': 'verbose'
        }

    def set_target(self) -> None:
        target = Targets().choose()

        Message.info('Selected {0}'.format(target.__name__))

        # Not all targets may need a value. For the moment it is the case, so let's assume we need the input.
        value = None
        while value is None or value is "":
            value = Message.input('<Choose {0}>: '.format(target().get_name()))

        target = target(value)

        self.targets.append(target)

        Message.info('Target {0} ({1}) was added.'.format(target.get_name(), target.get_value()))

    def list_targets(self) -> None:
        if len(self.targets) < 1:
            Message.info('No targets specified.')
        else:
            for target in self.targets:
                Message.info('{0} with value {1}'.format(target.get_name(), target.get_value()))

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
        if len(self.targets) < 1:
            self.set_target()

        if self.device is None:
            self.set_device()

        Capturer(self.verbose).capture(self.device)

    def show_welcome(self) -> None:
        delimiter = '{0}'.format('#' * 30)

        Message.info(delimiter)

        Message.info('#{0}#'.format('S N I F F E R'.center(28, ' ')))

        Message.info(delimiter)

    def main(self) -> None:
        self.show_welcome()

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
