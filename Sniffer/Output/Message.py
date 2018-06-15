class Message:
    @staticmethod
    def info(message: str) -> None:
        print('[+] {0}'.format(message))

    @staticmethod
    def input(message: str=None) -> str:
        return input('$ {0}'.format('' if message is None else message))
