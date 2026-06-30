import os
import sys
import glob
import ctypes
import ctypes.util
from typing import Optional

VOID_P = ctypes.c_void_p

class OpenSSL:
    def __init__(self):
        self.ssl: Optional[ctypes.CDLL] = None
        self.crypto: Optional[ctypes.CDLL] = None

        for path in OpenSSL.candidate_lib_paths("ssl"):
            try:
                self.ssl = ctypes.CDLL(path)
                break
            except OSError:
                continue

        if self.ssl is None:
            raise RuntimeError("Could not detect OpenSSL libssl. You can specify it using the KAEDE_OPENSSL/KAEDE_LIBSSL environ.")

        for path in OpenSSL.candidate_lib_paths("crypto"):
            try:
                self.crypto = ctypes.CDLL(path)
                break
            except OSError:
                continue

        if self.crypto is None:
            raise RuntimeError("Could not detect OpenSSL libcrypto. You can specify it using the KAEDE_OPENSSL/KAEDE_LIBCRYPTO environ.")

        self.configure()

    @staticmethod
    def candidate_lib_paths(name: str) -> list[str]:
        paths: list[str] = []

        env = os.environ.get(f"KAEDE_LIB{name.upper()}") or os.environ.get("KAEDE_OPENSSL")
        if env:
            if os.path.isdir(env):
                if sys.platform == "darwin":
                    paths.extend(sorted(glob.glob(os.path.join(env, f"lib{name}*.dylib")), reverse=True))
                else:
                    paths.extend(sorted(glob.glob(os.path.join(env, f"lib{name}*.so*")), reverse=True))
            else:
                basename = os.path.basename(env)
                if name in basename:
                    paths.append(env)

        if sys.platform == "darwin":
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
        else:
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

        seen: set[str] = set()
        unique: list[str] = []

        for path in paths:
            if path not in seen:
                seen.add(path)
                unique.append(path)

        return unique

    def configure(self):
        ...
