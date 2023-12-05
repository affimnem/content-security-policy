__all__ = ["get_file_hash"]

import hashlib
import mmap
from pathlib import Path
from sys import platform

CHUNK_SIZE = 1024 * 64  # 64 kb


# Newer versions of py hashlib have dedicated function for hashing files
def get_file_hash(path: Path, hash_name: str = "sha256") -> str:
    hash_factory = getattr(hashlib, hash_name)
    hash_obj = hash_factory()

    if path.stat().st_size != 0:  # Can not mmap empty files
        with open(path, "rb") as f:
            if platform == "linux":
                # Mmap significantly speeds up hashing while keeping memory footprint small
                map = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                hash_obj.update(map)
            else:  # TODO: mmap for windows and OSX
                while data := f.read(CHUNK_SIZE):
                    hash_obj.update(data)

    return hash_obj.hexdigest()
