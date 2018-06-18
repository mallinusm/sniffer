import datetime
import uuid
import os
import time

from Sniffer.Output.Message import Message


class Helpers:
    @staticmethod
    def get_timestamp() -> str:
        return datetime.datetime.now().strftime('%Y-%m-%d %H:%M')

    @staticmethod
    def bytes_to_utf8(payload: bytes) -> str:
        return str(payload, 'utf-8')

    @staticmethod
    def generate_unique_tmp_filename():
        # Make sure the float value of the unix timestamp contains 10 decimal places and 7 digits.
        # Obviously not very unique, but it's enough for this PoC.
        return '/tmp/sniffer/{:10.7f}'.format(time.time())

    @staticmethod
    def write_all_lines(data) -> None:
        filename = Helpers.generate_unique_tmp_filename()

        if not os.path.isdir('/tmp/sniffer'):
            os.makedirs('/tmp/sniffer')

        with open(filename, 'w') as file:
            file.write(data)

        Message.info('Created {0}'.format(filename))
