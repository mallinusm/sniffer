import json


class Bag:
    data = None

    def __init__(self, data: dict) -> None:
        self.data = data

    def get_attribute(self, key: str):  # Return value can be str, int, ...
        if key in self.data:
            return self.data.get(key)

        raise Exception('{0} not found.'.format(key))

    def set_attribute(self, key: str, value) -> None:
        if key in self.data:
            self.data[key] = value
        else:
            raise Exception('{0} cannot be set in bag.'.format(key))

    def to_string(self) -> str:
        return json.dumps(self.data)
