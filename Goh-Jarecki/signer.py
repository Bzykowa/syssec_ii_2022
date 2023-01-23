import argparse
import random
import sys
from common_protocol import Initiator
from klib import jstore
from mcl import Fr, G2

sys.path.insert(1, "/home/karolina/mcl-python")
GROUP_INIT = b"goh_jarecki"
GROUP_TYPE = G2


class Signer(Initiator):
    def __init__(self, ip: str, port: int, g: GROUP_TYPE) -> None:
        super().__init__(ip, port)
        self.g = g
        self.a = Fr()
        self.A = None
        self.m = None

        self.rn = Fr()
        self.g_hat = None
        self.A_hat = None
        self.s = Fr()
        self.h = Fr()

        # Generate public key
        self.a.setByCSPRNG()
        self.A = self.g * self.a

    def send_public_key(self):
        """Return A = g^a which is the public key"""
        return self.A

    def sign(self, m: str):
        """Create a signature."""
        # Random bits of 111 length
        r_bytes = random.randbytes(111)
        self.rn.deserialize(r_bytes)

        self.g_hat = GROUP_TYPE.hashAndMapTo((m + str(self.rn)).encode())
        self.A_hat = self.g_hat * self.a

        k = Fr()
        k.setByCSPRNG()

        u = self.g * k
        v = self.g_hat * k
        self.h = Fr.setHashOf(
            (str(self.g) + str(self.g_hat) +
             str(self.A) + str(self.A_hat) + str(u) + str(v)).encode()
        )
        self.s = k + self.a * self.h
        return self.rn, self.A_hat, self.s, self.h


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Goh Jarecki Signature Scheme - Signer")

    parser.add_argument("--ip", default="localhost",
                        help="IP address to bind to. Default: localhost")

    parser.add_argument("--port", default=15000, type=int,
                        help="Port to bind to. Default: 15000")
    args = parser.parse_args()

    group = GROUP_TYPE.hashAndMapTo(GROUP_INIT)
    signer = Signer(args.ip, args.port, group)

    A = signer.send_public_key()
    m = "Bardzo tajna wiadomosc"
    sigma = signer.sign(m)
    signer.send_message(jstore({"m": m, "sigma": sigma, "A": A}))
