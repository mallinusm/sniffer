class Packet:
    payload = None

    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def get_payload(self) -> bytes:
        return self.payload

    def get_payload_length(self) -> int:
        return len(self.payload)

    def to_string(self) -> str:
        return 'Class: {0}, Length: {1}'.format(self.__class__.__name__, self.get_payload_length())
