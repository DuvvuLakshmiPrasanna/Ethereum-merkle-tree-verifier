from Crypto.Hash import keccak


class _Keccak256Hasher:
    def __init__(self):
        self._hasher = keccak.new(digest_bits=256)

    def update(self, data: bytes) -> None:
        self._hasher.update(data)

    def digest(self) -> bytes:
        return self._hasher.digest()


def keccak_256():
    return _Keccak256Hasher()
