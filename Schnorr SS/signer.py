from mcl import G2, Fr
import sys
from common_protocol import Initiator
from klib import jstore

sys.path.insert(1, "/home/karolina/mcl-python")
group_init = b"schnorr_ss"
# HOSTNAME = "localhost"
HOSTNAME = "localhost"
PORT = 15000


class Signer(Initiator):

    def __init__(self, group_init, address: str, port: int) -> None:
        super().__init__(address, port)
        self.g = G2.hashAndMapTo(group_init)
        self.a = Fr()
        self.x = Fr()

        # Generate public key
        self.a.setByCSPRNG()
        self.A = self.g * self.a

    def send_public_key(self):
        """Return A = g^a which is the public key"""
        return self.A

    def sign(self, m: str):
        "Create signed message s = x + a*h"
        self.x.setByCSPRNG()
        X = self.g * self.x
        h = Fr.setHashOf((str(X) + m).encode())
        s = self.x + self.a * h
        return X, s


if __name__ == "__main__":
    signer = Signer(group_init, HOSTNAME, PORT)

    A = signer.send_public_key()
    m = "Bardzo tajna wiadomosc"
    X, s = signer.sign(m)
    signer.send_message(jstore({"A": A, "X": X, "m": m, "s": s}))
