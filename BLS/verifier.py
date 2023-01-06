from mcl import G1, G2, GT
import sys
from common_protocol import Responder
from klib import jload

sys.path.insert(1, "/home/karolina/mcl-python")
group_init = b"bls_ss"
# HOSTNAME = "localhost"
HOSTNAME = "localhost"
PORT = 15000


class Verifier(Responder):

    def __init__(self, group_init, address, port):
        super().__init__(address, port)
        self.g = G2.hashAndMapTo(group_init)

    def verify(self, X, m: str, S):
        """Verify the signature using pairing function."""
        h = G1.hashAndMapTo(m.encode())
        if GT.pairing(S, self.g) == GT.pairing(h, X):
            print("Accepted")
        else:
            print("Rejected")


if __name__ == "__main__":
    verifier = Verifier(group_init, HOSTNAME, PORT)
    m1 = verifier.receive_message()
    X, m, S = jload({"X": G2, "m": str, "S": G1}, m1)

    verifier.verify(X, m, S)
