import os
import sys
import glob
import ctypes
import ctypes.util
from typing import Optional, List

from .errors import TLSLibraryNotFoundError

VOID_P = ctypes.c_void_p

class OpenSSL:
    def __init__(self, *, ssl: Optional[ctypes.CDLL] = None, crypto: Optional[ctypes.CDLL] = None):
        self.ssl    = ssl or    OpenSSL.load_library("ssl")
        self.crypto = crypto or OpenSSL.load_library("crypto")

        self.configure()

    @staticmethod
    def load_library(name: str, required: bool = True) -> Optional[ctypes.CDLL]:
        for path in OpenSSL.candidate_paths(name):
            try:
                return ctypes.CDLL(path)
            except OSError:
                continue

        if required:
            raise TLSLibraryNotFoundError(f"Could not detect OpenSSL lib{name}. You can specify it using the KAEDE_OPENSSL/KAEDE_LIB{name.upper()} environ.")

    @staticmethod
    def candidate_paths(name: str) -> List[str]:
        paths: List[str] = []

        for path in [os.environ.get(f"KAEDE_LIB{name.upper()}", ""), os.environ.get("KAEDE_OPENSSL", "")]:
            if not path:
                continue

            if os.path.isdir(path):
                if sys.platform.startswith("darwin"):
                    paths.extend(sorted(glob.glob(os.path.join(path, f"lib{name}*.dylib")), reverse=True))

                elif sys.platform.startswith(("linux", "cygwin")):
                    paths.extend(sorted(glob.glob(os.path.join(path, f"lib{name}*.so*")), reverse=True))

            elif os.path.isfile(path):
                basename = os.path.basename(path)
                if f"lib{name}" in basename:
                    paths.append(path)

        if sys.platform.startswith("darwin"):
            patterns = [
                # OpenSSL 4.x
                f"/opt/homebrew/opt/openssl@4*/lib/lib{name}.dylib",
                f"/usr/local/opt/openssl@4*/lib/lib{name}.dylib",
                # OpenSSL 3.x
                f"/opt/homebrew/opt/openssl@3*/lib/lib{name}.dylib",
                f"/usr/local/opt/openssl@3*/lib/lib{name}.dylib",
                # Auto
                f"/opt/homebrew/lib/lib{name}.dylib",
                f"/usr/local/lib/lib{name}.dylib"
            ]
            for pattern in patterns:
                paths.extend(sorted(glob.glob(pattern), reverse=True))

        elif sys.platform.startswith(("linux", "cygwin")):
            patterns = [
                # OpenSSL 4.x
                f"/usr/lib/*/lib{name}.so.4",
                f"/usr/lib64/lib{name}.so.4",
                f"/usr/lib/lib{name}.so.4",
                f"/lib/*/lib{name}.so.4",
                f"/usr/local/lib/lib{name}.so.4",
                f"lib{name}.so.4",
                # OpenSSL 3.x
                f"/usr/lib/*/lib{name}.so.3",
                f"/usr/lib64/lib{name}.so.3",
                f"/usr/lib/lib{name}.so.3",
                f"/lib/*/lib{name}.so.3",
                f"/usr/local/lib/lib{name}.so.3",
                f"lib{name}.so.3",
                # Auto
                f"lib{name}.so"
            ]
            for pattern in patterns:
                paths.extend(sorted(glob.glob(pattern), reverse=True))

        found = ctypes.util.find_library(name)
        if found:
            paths.append(found)

        unique: List[str] = []

        for path in paths:
            if path not in unique:
                unique.append(path)

        return unique

    def configure(self):
        ...
