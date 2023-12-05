from typing import List


class ValuesMissing(Exception):  # pragma: no cover
    def __init__(self, message: str, names: List[str]):
        self.message = message
        self.names = names
