import datetime
import uuid

import os

from Sniffer.Output.Message import Message


class Helpers:
    @staticmethod
    def get_timestamp() -> str:
        return datetime.datetime.now().strftime('%Y-%m-%d %H:%M')

    @staticmethod
    def generate_unique_tmp_filename():
        return '/tmp/sniffer/{0}'.format(uuid.uuid4())

    @staticmethod
    def write_all_lines(data) -> None:
        filename = Helpers.generate_unique_tmp_filename()

        if not os.path.isdir('/tmp/sniffer'):
            os.makedirs('/tmp/sniffer')

        with open(filename, 'w') as file:
            file.write(data)

        Message.info('Created {0}'.format(filename))
