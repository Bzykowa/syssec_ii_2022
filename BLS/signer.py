from mcl import G1, G2, Fr
import sys
from common_protocol import Initiator
from klib import jstore

sys.path.insert(1, "/home/karolina/mcl-python")
group_init = b"bls_ss"

HOSTNAME = "localhost"
PORT = 15000


class Signer(Initiator):

    def __init__(self, group_init, address: str, port: int) -> None:
        super().__init__(address, port)
        self.g = G2.hashAndMapTo(group_init)
        self.x = Fr()

        # Generate public key
        self.x.setByCSPRNG()
        self.X = self.g * self.x

    def send_public_key(self):
        """Return X = g^x which is the public key"""
        return self.X

    def sign(self, m: str):
        "Create signed message S = h ^ x"
        h = G1.hashAndMapTo(m.encode())
        S = h * self.x
        return S


if __name__ == "__main__":
    signer = Signer(group_init, HOSTNAME, PORT)

    X = signer.send_public_key()
    m = "Bardzo tajna wiadomosc"

    S = signer.sign(m)
    signer.send_message(message=jstore({"X": X, "m": m, "S": S}))
