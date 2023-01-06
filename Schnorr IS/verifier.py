from mcl import G2, Fr
import sys
from common_protocol import Responder
from jlib import jload, jstore

sys.path.insert(1, "/home/karolina/mcl-python")
group_init = b"genQ"
HOSTNAME = "localhost"
# HOSTNAME = "192.168.159.130"
PORT = 15000


class Verifier(Responder):

    def __init__(self, group_init, address, port):
        super().__init__(address, port)
        self.g = G2.hashAndMapTo(group_init)
        self.c = Fr()
        self.s = Fr()

    def receive_public_key(self, A):
        """Get A = g^a from Prover"""
        self.A = A

    def receive_X(self, X):
        """Get X = g^x from Prover"""
        self.X = X

    def create_c(self):
        """Generate random challenge value"""
        self.c.setByCSPRNG()
        return self.c

    def receive_s(self, s):
        """Get s = x + a*c from Prover"""
        self.s = s

    def check_prover(self) -> bool:
        """Check if Prover submitted correct values"""
        return self.g * self.s == self.X + (self.A * self.c)


if __name__ == "__main__":
    verifier = Verifier(group_init, HOSTNAME, PORT)

    m1 = verifier.receive_message()
    A, X = jload({"A": G2, "X": G2}, m1)
    verifier.receive_public_key(A)
    verifier.receive_X(X)

    # Get c from Verifier
    c = verifier.create_c()
    verifier.send_message(jstore({"c": c}))

    m3 = verifier.receive_message()
    s = jload({"s": Fr}, m3)[0]
    verifier.receive_s(s)

    result = "Accepted" if verifier.check_prover() else "Rejected"
    verifier.send_message(result)
    print(result)
