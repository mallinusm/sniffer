class Packet:
    payload = None

    def __init__(self, payload: bytes):
        self.payload = payload

    def get_payload(self) -> bytes:
        return self.payload

    def get_payload_length(self) -> int:
        return len(self.payload)
