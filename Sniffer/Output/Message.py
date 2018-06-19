from Sniffer.Output.Colors import Colors


class Message:
    @staticmethod
    def info(message: str) -> None:
        print('{0}[+]{1} {2}'.format(Colors.GREEN, Colors.END, message))

    @staticmethod
    def input(message: str=None) -> str:
        return input('$ {0}{1}{2}'.format(Colors.BOLD, '' if message is None else message, Colors.END))
