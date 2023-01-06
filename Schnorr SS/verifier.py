from mcl import G2, Fr
import sys
from common_protocol import Responder
from klib import jload

sys.path.insert(1, "/home/karolina/mcl-python")
group_init = b"schnorr_ss"
# HOSTNAME = "localhost"
HOSTNAME = "localhost"
PORT = 15000


class Verifier(Responder):

    def __init__(self, group_init, address, port):
        super().__init__(address, port)
        self.g = G2.hashAndMapTo(group_init)

    def verify(self, A, X, m: str, s):
        h = Fr.setHashOf((str(X) + m).encode())
        if self.g * s == X + (A*h):
            print("Accepted")
        else:
            print("Rejected")


if __name__ == "__main__":
    verifier = Verifier(group_init, HOSTNAME, PORT)
    m1 = verifier.receive_message()
    A, X, m, s = jload({"A": G2, "X": G2, "m": str, "s": Fr}, m1)

    verifier.verify(A, X, m, s)
