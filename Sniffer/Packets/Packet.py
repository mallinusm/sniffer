class Packet:
    payload = None

    def __init__(self, payload: bytes):
        self.payload = payload

    def get_payload(self) -> bytes:
        return self.payload

    def get_payload_length(self) -> int:
        return len(self.payload)

    def to_string(self) -> str:
        return 'Length: {0}'.format(self.get_payload_length())
